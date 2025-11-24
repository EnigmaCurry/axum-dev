use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

use super::ids::{TodoId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Todo {
    pub id: TodoId,
    pub user_id: UserId,
    pub title: String,
    pub notes: Option<String>,
    pub completed: bool,
    pub due_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// #[derive(Debug, Deserialize)]
// pub struct CreateTodo {
//     pub title: String,
//     pub notes: Option<String>,
//     pub due_at: Option<DateTime<Utc>>,
// }

// #[derive(Debug, Deserialize)]
// pub struct UpdateTodo {
//     pub title: Option<String>,
//     pub notes: Option<Option<String>>, // Some(None) means “clear notes”
//     pub completed: Option<bool>,
//     pub due_at: Option<Option<DateTime<Utc>>>,
// }
