use askama::Template;

#[derive(Template)]
#[template(path = "pages/index.html")]
pub struct IndexTemplate {
    pub title: String,
}
