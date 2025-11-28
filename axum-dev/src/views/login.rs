use askama::Template;

#[derive(Template)]
#[template(path = "pages/login.html")]
pub struct LoginTemplate {
    pub title: String,
}
