use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FamilyId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InviteId(pub Uuid);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Blocked,
    Pending,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    Invited,
    Active,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Mobile,
    Tablet,
    Desktop,
    Browser,
    Api,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshSession {
    pub family_id: FamilyId,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub current_jti_hash: String,
    pub device_name: String,
    pub device_type: DeviceType,
    pub created_at: DateTime<Utc>,
    pub last_rotated_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub is_current: bool,
    pub is_trusted: bool,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::DeviceType;

    #[test]
    fn serializes_device_type_as_snake_case() {
        let encoded = serde_json::to_string(&DeviceType::Mobile).expect("serialize device type");
        assert_eq!(encoded, "\"mobile\"");
    }
}
