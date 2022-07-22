# Release Guide for Discovery Engine

### How to create a new stable release for discovery engine?

* create a branch v0.x
* wait for the images to be created for v0.x in [docker hub](https://hub.docker.com/r/accuknox/knoxautopolicy/tags)
* Update [STABLE-RELEASE](../STABLE-RELEASE) to v0.x ... push the updated `STABLE-RELEASE` to `dev` branch
* verify that the `stable` and `v0.x` digests match in the [docker hub](https://hub.docker.com/r/accuknox/knoxautopolicy/tags)

