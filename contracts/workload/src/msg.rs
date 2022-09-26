use cosmwasm_std::{Uint128, Timestamp, Binary};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::state::{Provider, WorkloadInfo};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub admin: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ExecuteAIMsgDetail {
    pub provider_id: Uint128, 
    pub nft_addr: String, 
    pub token_id: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // AddWhitelistedRegister { whitelisted_register: String},
    AllowProvider { provider_id: Uint128 },
    RegisterProvider { name: String, price: Uint128, expires: Timestamp, execution_limit: Uint128, supported_nfts: Vec<String>, endpoint: String },
    ExecuteAI { 
        msg: ExecuteAIMsgDetail,
        pubkey: Binary,
    },
    UpdateWorkloadStatus { 
        workload_id: Uint128,
        pubkey: Binary,
        // sig_msg: Binary, 
        // signature_hash: Binary,
     },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // ResolveAddress returns the current address that the name resolves to
    GetProviderById { id: Uint128 },
    GetWorkloadStatus { workload_id: Uint128 },
    GetProviderCount {},
    GetAllowedWorkload { pubkey: Binary, workload_id: Uint128 }
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ResolveRecordResponse {
    pub address: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct  ProviderResponse {
    pub provider: Option<Provider>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WorkloadInfoResponse {
    pub workload: Option<WorkloadInfo>
}
