# rust-axum-template

This is my [Axum](https://github.com/tokio-rs/axum) server template for new
Rust web projects.

This is ALPHA software in-development.

## Features

For the full list of features, see the embedded
[README.md](template/README.md) inside the template.

## How to use this template

 * [Create a new repository using this template](https://github.com/new?template_name=rust-axum-template&template_owner=EnigmaCurry).
 * The `Repository name` that you choose will also become the name of
   your new app.
 * Go to the GitHub repository `Settings` page:
   * Find `Pages`.
   * Find `Build and deployment`.
   * Find `Source` and set it to `GitHub Actions`. (**Not** `Deploy
     from a branch`)

## Clone your new repository to your workstation.

```
## For example:
FORGE=github.com
USERNAME=your_username
REPOSITORY=your_repository

git clone git@${FORGE}:${USERNAME}/${REPOSITORY}.git \
   ~/git/vendor/${USERNAME}/${REPOSITORY}

cd ~/git/vendor/${USERNAME}/${REPOSITORY}
```

## Render the template

After cloning the repository to your workstation, you must initialize
 it:

```
./setup.sh
```

This will render the template files into the project root and then
self-destruct this README.md and the template.

It will also build and run the initial tests. Importantly, this will
also create the Cargo.lock file for the first time.

## Commit the initial app source files

Once you've verified that the tests ran correctly, you can add all of
the files the template generated, as well as the `Cargo.lock` file,
into the git repository. Commit and push your changes:

```
## For example:

git add .
git commit -m "init"
git push
```

You're now ready to start developing your application.

## Releasing your app

See [DEVELOPMENT.md](template/DEVELOPMENT.md) for instructions on the
release process, a copy of this file has been included in your new git
repository's root.
 
