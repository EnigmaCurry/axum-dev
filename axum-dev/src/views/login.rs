use askama::Template;

#[derive(Template)]
#[template(path = "pages/login.html")]
pub struct LoginTemplate {
    pub title: String,
    pub logged_in: bool,
    pub external_user_id: Option<String>,
    pub csrf_token: String,
}
