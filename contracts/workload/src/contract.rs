use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult, Uint128,  Addr, coin, SubMsg, BankMsg, Empty, from_binary
};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ProviderResponse, WorkloadInfoResponse, ExecuteAIMsgDetail, InputMsg};
use crate::state::{ADMIN, PROVIDER_COUNT, WORKLOAD_INFO, WORKLOAD_COUNT, Provider, WorkloadInfo,  WorkloadStatus, PROVIDER_INFO};
use cw721_base::QueryMsg as Cw721QueryMsg;
use cw721_base::Metadata;
use cw721::{NftInfoResponse};
use ripemd::{Ripemd160};
use bech32::{self, ToBase32, Variant};
use sha2::{Digest, Sha256};

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
        ExecuteMsg::ExecuteAlgorithm { msg } => execute_algorithm(deps, env, info, msg),
        ExecuteMsg::UpdateWorkloadStatus { msg, signature, pubkey } =>  update_workload_status(deps, info, msg, signature, pubkey),
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
    // signature_hash: String,
) -> Result<Response, ContractError> { 


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
    payout(deps.as_ref(), provider_info.price, provider_info.register.clone(), &mut res)?;
    
    // Get docker url from AI NFT
    let nft_info: NftInfoResponse<Metadata> = deps.querier.query_wasm_smart(nft_addr, &Cw721QueryMsg::<Empty>::NftInfo { token_id })?;
    let docker_img_url = nft_info.extension.docker_img_url;

    let mut workload_id = WORKLOAD_COUNT.load(deps.storage)?;

    let workload_info = WorkloadInfo {
        provider_id,
        executor: provider_info.register,
        time: env.block.time,
        status: WorkloadStatus::Running,
        docker_img_url: docker_img_url.clone(),
        caller: info.sender.to_string(),
    };

    WORKLOAD_INFO.save(deps.storage, workload_id.to_string(), &workload_info)?;

    res = res.add_attribute("workload_id", workload_id);

    workload_id += Uint128::from(1 as u32);
    WORKLOAD_COUNT.save(deps.storage, &workload_id)?;
    
    Ok(
        res.add_attribute("endpoint", provider_info.endpoint)
            .add_attribute("docker_img_url", docker_img_url)
    )
}

pub fn update_workload_status(
    deps: DepsMut,
    _info: MessageInfo,
    msg: String, 
    signature_hash: String, 
    pubkey_base64: String,
) -> Result<Response, ContractError> {
    // let input_msg: InputMsg = from_binary(&Binary::from_base64(&msg)?)?;

    let workload_id: Uint128 = msg.parse().unwrap();
    let mut workload = query_authorized_workload(deps.as_ref(), msg.clone(), signature_hash, pubkey_base64)?;

    workload.status = WorkloadStatus::Completed;
    WORKLOAD_INFO.save(deps.storage, workload_id.to_string(), &workload)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetProviderById { id } => to_binary(&query_provider_by_id(deps, env, id)?),
        QueryMsg::GetWorkloadStatus { workload_id } => to_binary(&query_workload_info_by_id(deps, workload_id)?),
        QueryMsg::GetProviderCount {} => to_binary(&query_provider_count(deps, env)?),
        QueryMsg::GetAllowedWorkload { pubkey, workload_id } => to_binary(&query_is_authorized_executor(deps, pubkey, workload_id)?),
        QueryMsg::GetAuthorizedWorkload {msg, signature_hash, pubkey_base64} => to_binary(&query_authorized_workload(deps, msg, signature_hash, pubkey_base64)?),
    }
}

fn query_provider_by_id(deps: Deps, _env: Env, id: Uint128) -> StdResult<ProviderResponse> {
    let provider = PROVIDER_INFO.may_load(deps.storage, id.to_string())?;
    Ok(ProviderResponse {provider})
}

fn query_authorized_workload(
    deps: Deps, 
    msg: String, 
    signature_hash: String,
    pubkey_base64: String
) -> StdResult<WorkloadInfo> {
    let workload_id: Uint128 = msg.parse().unwrap();
    let workload_info = query_workload_info_by_id(deps, workload_id)?;

    if workload_info.workload.is_none() {
        return Err(StdError::generic_err(
                    "No such workload",
                ));
    }

    let workload = workload_info.workload.unwrap();

    let pubkey = Binary::from_base64(&pubkey_base64)?;
    let addr = pubkey_to_address(&pubkey).unwrap();

    if addr.ne(&workload.caller) {
        return Err(StdError::generic_err(
            "Verification failed. Caller is not authorized",
        ));
    }

    let mut msg_adr36:Vec<u8> = vec![123,34,97,99,99,111,117,110,116,95,110,117,109,98,101,114,34,58,34,48,34,44,34,99,104,97,105,110,95,105,100,34,58,34,34,44,34,102,101,101,34,58,123,34,97,109,111,117,110,116,34,58,91,93,44,34,103,97,115,34,58,34,48,34,125,44,34,109,101,109,111,34,58,34,34,44,34,109,115,103,115,34,58,91,123,34,116,121,112,101,34,58,34,115,105,103,110,47,77,115,103,83,105,103,110,68,97,116,97,34,44,34,118,97,108,117,101,34,58,123,34,100,97,116,97,34,58,34];
    msg_adr36.append(&mut base64::encode(msg).as_bytes().to_vec());
    msg_adr36.append(&mut vec![34,44,34,115,105,103,110,101,114,34,58,34]);
    msg_adr36.append(&mut addr.clone().as_bytes().to_vec());
    msg_adr36.append(&mut vec![34,125,125,93,44,34,115,101,113,117,101,110,99,101,34,58,34,48,34,125]);

    let hash = Sha256::digest(&msg_adr36);

    let signature = Binary::from_base64(&signature_hash)?;
    let pubkey = Binary::from_base64(&pubkey_base64)?;

    let is_verified = deps.api.secp256k1_verify(hash.as_ref(), signature.as_slice(), pubkey.as_slice()).unwrap();
    if !is_verified {
        return Err(StdError::generic_err(
            "Verification failed.",
        ));
    }

    Ok(workload)
}

fn query_workload_info_by_id(
    deps: Deps, 
    workload_id: Uint128, 
) -> StdResult<WorkloadInfoResponse> {
    let workload = WORKLOAD_INFO.may_load(deps.storage, workload_id.to_string())?;

    Ok(WorkloadInfoResponse { workload })
}

fn query_provider_count(deps: Deps, _env: Env) -> StdResult<Uint128> {
    let provider_count = PROVIDER_COUNT.load(deps.storage)?;
    Ok(provider_count)
}

fn query_is_authorized_executor(deps: Deps, pubkey: Binary, workload_id: Uint128) -> StdResult<Option<WorkloadInfo>> {
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
