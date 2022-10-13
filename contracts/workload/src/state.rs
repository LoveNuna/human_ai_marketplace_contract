use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Uint128, Timestamp, BlockInfo};
use cw_storage_plus::{Item, IndexedMap, MultiIndex, IndexList, Index, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]pub struct Config {
    pub admin: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ImageInfo {
    pub docker_url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct NftInfo {
    pub nft_addr: String,
    pub nft_id: String,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Provider {
    pub provider_id: Uint128,
    pub register: String,
    pub name: String,
    pub price: Uint128, 
    pub expires: Timestamp, 
    pub execution_limit: Uint128, 
    pub supported_nfts: Vec<String>,
    pub execution_count: Uint128,
    pub is_allowed: bool,
    pub endpoint: String,
}

impl Provider {
    pub fn is_expired(&self, block: &BlockInfo) -> bool {
        self.expires <= block.time
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum WorkloadStatus {
    Idle,
    Running,
    Completed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct WorkloadInfo {
    pub provider_id: Uint128,
    pub executor: String,
    pub time: Timestamp,
    pub status: WorkloadStatus,   // 0: Not running, 1: running, 2: finished
    pub docker_img_url: String,
    pub caller: String,
}

// Primary key for providers: (provider_id, register)
pub type ProviderKey = Uint128;

pub fn provider_key(provider_id: Uint128, register: &Addr) -> ProviderKey {
    provider_id
}

/// Defines indices for accessing Providers
pub struct ProviderIndices<'a> {
    pub register: MultiIndex<'a, Addr, Provider, ProviderKey>,
    // pub id: MultiIndex<'a, u128, Provider, ProviderKey>
}

impl<'a> IndexList<Provider> for ProviderIndices<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Provider>> + '_> {
        let v: Vec<&dyn Index<Provider>> = vec![&self.register];
        Box::new(v.into_iter())
    }
}

// pub fn providers<'a>() -> IndexedMap<'a, ProviderKey, Provider, ProviderIndices<'a>> {
//     let indexes = ProviderIndices {
//         register: MultiIndex::new(|d: &Provider| d.register.clone(), "providers", "providers__seller"),
//         // id: MultiIndex::new(|d: &Provider| d.provider_id, "providers", "providers__id"),
//     };
//     IndexedMap::new("providers", indexes)
// }

pub const ADMIN: Item<Addr> = Item::new("admin");
pub const PROVIDER_COUNT: Item<Uint128> = Item::new("providers__count");
pub const WORKLOAD_COUNT: Item<Uint128> = Item::new("Workload__count");

pub const WORKLOAD_INFO: Map<String, WorkloadInfo> = Map::new("Workload__info");
pub const PROVIDER_INFO: Map<String, Provider> = Map::new("provider__info");
