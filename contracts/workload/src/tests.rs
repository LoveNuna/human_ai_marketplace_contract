#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, Coin, Uint128, Binary};

    use crate::contract::{execute, instantiate, query};
    use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, ProviderResponse, ExecuteAIMsgDetail};
    use crate::state::{Provider};

    #[test]
    fn register_and_allow_providers() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let env = mock_env();

        let instantiate_msg = InstantiateMsg {
            admin: "admin".to_string()
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), instantiate_msg).unwrap();

        // Register a new provider
        let info = mock_info("register1", &[]);
        let msg = ExecuteMsg::RegisterProvider {
            name: "provider1".to_string(),
            price: Uint128::from(10 as u32),
            expires: 1000,
            execution_limit: Uint128::from(2 as u32),
            supported_nfts: vec!["nft_address1".to_string()],
            endpoint: "https://example.com".to_string(),
        };

        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let query_provider_msg = QueryMsg::GetProviderById { id: Uint128::from(0 as u32) };
        let res = query(deps.as_ref(), mock_env(), query_provider_msg).unwrap();
        let provider: ProviderResponse = from_binary(&res).unwrap();

        assert_eq!(provider.provider.unwrap(), Provider { 
            provider_id: Uint128::from(0 as u32),
            register: "register1".to_string(), 
            name: "provider1".to_string(), 
            price: Uint128::from(10 as u32), 
            expires: env.block.time.plus_seconds(1800), 
            execution_limit: Uint128::from(2 as u32), 
            supported_nfts: vec!["nft_address1".to_string()], 
            execution_count: Uint128::from(0 as u32), 
            is_allowed: false, 
            endpoint: "https://example.com".to_string()
        });

        // Allow provider 
        let info = mock_info("admin", &[]);
        let allow_msg = ExecuteMsg::AllowProvider { provider_id: Uint128::from(0 as u32) };
        execute(deps.as_mut(), env.clone(), info, allow_msg).unwrap();

        let query_provider_msg = QueryMsg::GetProviderById { id: Uint128::from(0 as u32) };
        let res = query(deps.as_ref(), mock_env(), query_provider_msg).unwrap();
        let provider: ProviderResponse = from_binary(&res).unwrap();

        assert_eq!(provider.provider.unwrap(), Provider { 
            provider_id: Uint128::from(0 as u32),
            register: "register1".to_string(), 
            name: "provider1".to_string(), 
            price: Uint128::from(10 as u32), 
            expires: env.block.time.plus_seconds(1800), 
            execution_limit: Uint128::from(2 as u32), 
            supported_nfts: vec!["nft_address1".to_string()], 
            execution_count: Uint128::from(0 as u32), 
            is_allowed: true, 
            endpoint: "https://example.com".to_string()
        });

    }

    #[test]
    fn execute_algorithms() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let env = mock_env();

        let instantiate_msg = InstantiateMsg {
            admin: "admin".to_string()
        };

        instantiate(deps.as_mut(), env.clone(), info.clone(), instantiate_msg).unwrap();

        // Register a new provider
        let info = mock_info("register1", &[]);
        let msg = ExecuteMsg::RegisterProvider {
            name: "provider1".to_string(),
            price: Uint128::from(10 as u32),
            expires: 1000,
            execution_limit: Uint128::from(2 as u32),
            supported_nfts: vec!["nft_address1".to_string()],
            endpoint: "https://example.com".to_string(),
        };

        execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Allow provider 
        let info = mock_info("admin", &[]);
        let allow_msg = ExecuteMsg::AllowProvider { provider_id: Uint128::from(0 as u32) };
        execute(deps.as_mut(), env.clone(), info, allow_msg).unwrap();

        // Execute AI algorithm
        let info = mock_info("human14n3tx8s5ftzhlxvq0w5962v60vd82h30jt9eya", &[Coin {denom: "uheart".to_string(), amount: Uint128::from(10 as u32)}]);
        let execute_algorithm_msg = ExecuteMsg::ExecuteAlgorithm { 
            msg: ExecuteAIMsgDetail {
                provider_id: Uint128::from(0 as u32), 
                nft_addr: "nft_address1".to_string(), 
                token_id: "token1".to_string(),
            },
            pubkey: Binary::from_base64("AipQCudhlHpWnHjSgVKZ+SoSicvjH7Mp5gCFyDdlnQtn").unwrap()
         };

        let res = execute(deps.as_mut(), env.clone(), info, execute_algorithm_msg).unwrap();
        println!("response: {:?}", res);
    }
}
