use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128,  Addr, coin, SubMsg, BankMsg, Empty
};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ProviderResponse, WorkloadInfoResponse, ExecuteAIMsgDetail};
use crate::state::{ADMIN, PROVIDER_COUNT, WORKLOAD_INFO, WORKLOAD_COUNT, Provider, WorkloadInfo,  WorkloadStatus, PROVIDER_INFO};
use cw721_base::QueryMsg as Cw721QueryMsg;
use cw721_base::Metadata;
use cw721::{NftInfoResponse};
use sha2::{Digest};
use ripemd::{Ripemd160};
use bech32::{self, ToBase32, Variant};

// use base64::encode;
// use cosmwasm_crypto::secp256k1_verify;


pub const NATIVE_DENOM: &str = "uheart";

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, StdError> {
    // Set the admin
    let admin = deps.api.addr_validate(msg.admin.as_str())?;
    ADMIN.save(deps.storage, &admin)?;

    // initialize the index numbers of Provider and Executor
    PROVIDER_COUNT.save(deps.storage, &Uint128::zero())?;
    WORKLOAD_COUNT.save(deps.storage, &Uint128::zero())?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::AllowProvider { provider_id } => allow_provider(deps, env, info, provider_id),
        ExecuteMsg::RegisterProvider { name, price, expires, execution_limit, supported_nfts, endpoint } => register_provider(deps, env, info, name, price, expires, execution_limit, supported_nfts, endpoint),
        ExecuteMsg::ExecuteAlgorithm { msg, pubkey} => execute_algorithm(deps, env, info, msg, pubkey),
        ExecuteMsg::UpdateWorkloadStatus { workload_id, pubkey } =>  update_workload_status(deps, env, info, workload_id, pubkey),
    }
}

pub fn allow_provider(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    provider_id: Uint128
) -> Result<Response, ContractError> { 
    let admin = ADMIN.load(deps.storage)?;
    
    if info.sender.ne(&admin) {
        return Err(ContractError::Unauthorized {  });
    } 

    let mut provider = PROVIDER_INFO.load(deps.storage, provider_id.to_string())?;
    provider.is_allowed = true;
    PROVIDER_INFO.save(deps.storage, provider_id.to_string(), &provider)?;

    Ok(Response::default())
}

pub fn register_provider(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    name: String,
    price: Uint128, 
    expires: u64, 
    execution_limit: Uint128, 
    supported_nfts: Vec<String>,
    endpoint: String
) -> Result<Response, ContractError> {
    let mut provider_count = PROVIDER_COUNT.load(deps.storage)?;

    let mut supported_nft_addr: Vec<String> = vec![];
    for nft_addr in supported_nfts {
        deps.api.addr_validate(nft_addr.as_str())?;
        supported_nft_addr.push(nft_addr);
    }

    let provider_info = Provider {
        provider_id: provider_count,
        register: info.sender.to_string(),
        name,
        price,
        expires: env.block.time.plus_seconds(expires),
        execution_limit,
        supported_nfts: supported_nft_addr,
        execution_count: Uint128::zero(),
        is_allowed: false,
        endpoint,
    };

    PROVIDER_INFO.save(deps.storage, provider_count.to_string(), &provider_info)?;

    provider_count += Uint128::from(1 as u32);
    PROVIDER_COUNT.save(deps.storage, &provider_count)?;

    Ok(Response::default())
}

pub fn execute_algorithm(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteAIMsgDetail,
    pubkey: Binary,
) -> Result<Response, ContractError> {
    let addr = pubkey_to_address(&pubkey)?;

    if addr.ne(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }

    let provider_id = msg.provider_id;
    let nft_addr = msg.nft_addr;
    let token_id = msg.token_id;

    let provider = query_provider_by_id(deps.as_ref(), env.clone(), provider_id)?.provider;

    if provider.is_none() {
        return Err(ContractError::NoSuchProvider {});
    }

    let mut provider_info = provider.unwrap();

    if !provider_info.is_allowed {
        return Err(ContractError::NotAllowed {});
    }

    if provider_info.is_expired(&env.block) {
        return Err(ContractError::Expired {});
    }

    if provider_info.price != Uint128::zero() {
        if info.funds.len() != 1 {
            return Err(ContractError::WrongPayment {});
        }

        if info.funds[0].denom != NATIVE_DENOM || info.funds[0].amount != provider_info.price {
            return Err(ContractError::WrongPayment {});
        }
    }

    if !provider_info.supported_nfts.contains(&nft_addr) {
        return Err(ContractError::NotSupportedNft {});
    }

    if provider_info.execution_count >= provider_info.execution_limit {
        return Err(ContractError::ExecutionLimitOverflow {});
    }

    // Update the provider information
    provider_info.execution_count += Uint128::from(1 as u32);
    PROVIDER_INFO.save(deps.storage, provider_id.to_string(), &provider_info)?;

    // pay creator for the usage
    let mut res = Response::new();
    payout(deps.as_ref(), provider_info.price, provider_info.register, &mut res)?;
    
    // Get docker url from AI NFT
    let nft_info: NftInfoResponse<Metadata> = deps.querier.query_wasm_smart(nft_addr, &Cw721QueryMsg::<Empty>::NftInfo { token_id })?;
    let docker_img_url = nft_info.extension.docker_img_url;

    let mut workload_id = WORKLOAD_COUNT.load(deps.storage)?;

    let workload_info = WorkloadInfo {
        provider_id,
        executor: info.sender,
        time: env.block.time,
        status: WorkloadStatus::Running,
        docker_img_url: docker_img_url.clone(),
    };

    WORKLOAD_INFO.save(deps.storage, workload_id.to_string(), &workload_info)?;

    workload_id += Uint128::from(1 as u32);
    WORKLOAD_COUNT.save(deps.storage, &workload_id)?;
    
    Ok(
        res.add_attribute("endpoint", provider_info.endpoint)
            .add_attribute("docker_img_url", docker_img_url)
            .add_attribute("workload_id", workload_id)
    )
}

pub fn update_workload_status(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    workload_id: Uint128,
    pubkey: Binary,
    // sig_msg: Binary,
    // signature_hash: Binary,
) -> Result<Response, ContractError> {
    let admin = ADMIN.load(deps.storage)?;

    if info.sender != admin {
        return  Err(ContractError::Unauthorized { });
    }

    let workload_info = query_is_authorized_executor(deps.as_ref(), env, pubkey, workload_id)?;
    if workload_info.is_none() {
        return Err(ContractError::Unauthorized {});
    }

    let mut workload = workload_info.unwrap();

    if workload.status != WorkloadStatus::Running {
        return Err(ContractError::NotRunningWorkload { });
    }

    // let pubkey = workload.clone().executor;
    // let is_signed = secp256k1_verify(sig_msg.as_slice(), signature_hash.as_slice(),  pubkey.as_slice()).unwrap();
    // if !is_signed {
    //     return  Err(ContractError::Unauthorized { });
    // }

    workload.status = WorkloadStatus::Completed;
    WORKLOAD_INFO.save(deps.storage, workload_id.to_string(), &workload)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProviderById { id } => to_binary(&query_provider_by_id(deps, env, id)?),
        QueryMsg::GetWorkloadStatus { workload_id } => to_binary(&query_workload_info_by_id(deps, env, workload_id)?),
        QueryMsg::GetProviderCount {} => to_binary(&query_provider_count(deps, env)?),
        QueryMsg::GetAllowedWorkload { pubkey, workload_id } => to_binary(&query_is_authorized_executor(deps, env, pubkey, workload_id)?),
    }
}

fn query_provider_by_id(deps: Deps, _env: Env, id: Uint128) -> StdResult<ProviderResponse> {
    let provider = PROVIDER_INFO.may_load(deps.storage, id.to_string())?;
    Ok(ProviderResponse {provider})
}

fn query_workload_info_by_id(deps: Deps, _env: Env, workload_id: Uint128) -> StdResult<WorkloadInfoResponse> {
    let workload = WORKLOAD_INFO.may_load(deps.storage, workload_id.to_string())?;
    Ok(WorkloadInfoResponse { workload })
}

fn query_provider_count(deps: Deps, _env: Env) -> StdResult<Uint128> {
    let provider_count = PROVIDER_COUNT.load(deps.storage)?;
    Ok(provider_count)
}

fn query_is_authorized_executor(deps: Deps, _env: Env, pubkey: Binary, workload_id: Uint128) -> StdResult<Option<WorkloadInfo>> {
    let addr = pubkey_to_address(&pubkey).unwrap();
    let workload_info = WORKLOAD_INFO.load(deps.storage, workload_id.to_string())?;

    if workload_info.executor.ne(&addr) {
        return Ok(None);
    }
    Ok(Some(workload_info))
}

fn payout(
    _deps: Deps,
    payment: Uint128,
    payment_recipient: String,
    res: &mut Response,
) -> StdResult<()> {
    let amount = coin(payment.u128(), NATIVE_DENOM);

    res.messages.push(SubMsg::new(BankMsg::Send {
        to_address: payment_recipient,
        amount: vec![amount.clone()],
    }));

    Ok(())
}

pub fn pubkey_to_address(pubkey: &Binary) -> Result<Addr, ContractError> {
    let msg_hash_generic = sha2::Sha256::digest(pubkey.as_slice());
    let msg_hash = msg_hash_generic.as_slice();
    let mut hasher = Ripemd160::new();
    hasher.update(msg_hash);
    let result = hasher.finalize();
    let result_slice = result.as_slice();
    let encoded = bech32::encode("human", result_slice.to_base32(), Variant::Bech32)
        .map_err(|err| ContractError::Std(StdError::generic_err(err.to_string())))?;
    Ok(Addr::unchecked(encoded))
}
