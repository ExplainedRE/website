
<img src="static/images/explained.svg" width="50%">

**This repository contains the content of the [explained.re](https://explained.re) website.**

Found an issue? Have a suggestion? Please open an issue or a Pull-Request on this repository. Alternatively, [contact us on Twitter](https://twitter.com/ExplainedRE).


### Build the website locally
Building "explained.re" on your local machine is simple and straight forward. First, make sure you have the "**extended**" version of `hugo` installed on your machine. Hugo's [documentation](https://gohugo.io/getting-started/installing/) will walk you through the installation of Hugo to your environment.
Then, clone this repository and its submodules and "serve" the website:

```
git clone --recurse-submodules https://github.com/ExplainedRE/website
cd website
hugo serve
```


### Deployment
A new version of the website will automatically be built and deployed to Github Pages upon a push to the master branch.
Using Github Actions, a push to the master branch will trigger an action that will use `hugo` to build the website and push it to the `gh-pages` branch. This branch will be used by Github Pages to serve the Website.