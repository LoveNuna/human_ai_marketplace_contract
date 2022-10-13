use cosmwasm_std::{Uint128, Binary};
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
pub struct InputMsg {
    pub input: String, 
    pub workload_id: Uint128, 
}

// impl fmt::Display for InputMsg {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "input: {}, workload_id: {})", self.input, self.workload_id)
//     }
// }

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // AddWhitelistedRegister { whitelisted_register: String},
    AllowProvider { provider_id: Uint128 },
    RegisterProvider { name: String, price: Uint128, expires: u64, execution_limit: Uint128, supported_nfts: Vec<String>, endpoint: String },
    ExecuteAlgorithm { 
        msg: ExecuteAIMsgDetail,
    },
    UpdateWorkloadStatus {
        msg: String,
        signature: String,
        pubkey: String,
     },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // ResolveAddress returns the current address that the name resolves to
    GetProviderById { id: Uint128 },
    GetWorkloadStatus { workload_id: Uint128 },
    GetProviderCount {},
    GetAllowedWorkload { pubkey: Binary, workload_id: Uint128 },
    GetAuthorizedWorkload { msg: String, signature_hash: String, pubkey_base64: String},
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
