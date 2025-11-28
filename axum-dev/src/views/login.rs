use askama::Template;

#[derive(Template)]
#[template(path = "pages/login.html")]
pub struct LoginTemplate {
    pub title: String,
    pub logged_in: bool,
    pub user_name: String,
}
