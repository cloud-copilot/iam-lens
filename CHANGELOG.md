## [0.1.84](https://github.com/cloud-copilot/iam-lens/compare/v0.1.83...v0.1.84) (2026-02-20)


### Bug Fixes

* Post denied who-can simulations from workers to the main thread to ensure simulationCount is accurate ([1709009](https://github.com/cloud-copilot/iam-lens/commit/170900955bf374aa611194783820577322576baa))


### Features

* Run who-can with resource patterns ([801e92c](https://github.com/cloud-copilot/iam-lens/commit/801e92c40d6f24ce5ca6671ba45824d371f420c5))

## [0.1.83](https://github.com/cloud-copilot/iam-lens/compare/v0.1.82...v0.1.83) (2026-02-20)

## [0.1.82](https://github.com/cloud-copilot/iam-lens/compare/v0.1.81...v0.1.82) (2026-02-15)


### Bug Fixes

* Remove guarddog rule causing false positives ([99ce39b](https://github.com/cloud-copilot/iam-lens/commit/99ce39ba81d41a3512008ea63465fe9b7aec70f6))

## [0.1.81](https://github.com/cloud-copilot/iam-lens/compare/v0.1.80...v0.1.81) (2026-02-14)

## [0.1.80](https://github.com/cloud-copilot/iam-lens/compare/v0.1.79...v0.1.80) (2026-01-19)

## [0.1.79](https://github.com/cloud-copilot/iam-lens/compare/v0.1.78...v0.1.79) (2026-01-11)

## [0.1.78](https://github.com/cloud-copilot/iam-lens/compare/v0.1.77...v0.1.78) (2026-01-08)


### Features

* Add the ability to get deny details from whoCan ([8be2907](https://github.com/cloud-copilot/iam-lens/commit/8be2907c873f7479c603e849c9c518a6173087c7))

## [0.1.77](https://github.com/cloud-copilot/iam-lens/compare/v0.1.76...v0.1.77) (2026-01-03)


### Features

* Allow configuring the number of who-can worker threads. ([87fe61f](https://github.com/cloud-copilot/iam-lens/commit/87fe61f1717ed6a8721e30ac719b8fcdf067dca4))

## [0.1.76](https://github.com/cloud-copilot/iam-lens/compare/v0.1.75...v0.1.76) (2026-01-03)

## [0.1.75](https://github.com/cloud-copilot/iam-lens/compare/v0.1.74...v0.1.75) (2026-01-03)


### Features

* Add cross account S3 buckets to principal-can ([9cfbb86](https://github.com/cloud-copilot/iam-lens/commit/9cfbb86e96ae87dc916f22a68186617f1ca9ad9e))

## [0.1.74](https://github.com/cloud-copilot/iam-lens/compare/v0.1.73...v0.1.74) (2025-12-28)

## [0.1.73](https://github.com/cloud-copilot/iam-lens/compare/v0.1.72...v0.1.73) (2025-12-24)


### Features

* Support session policies in simulate ([ee7d95b](https://github.com/cloud-copilot/iam-lens/commit/ee7d95bd6b98998b22f6166a63c242927113ecf4))

## [0.1.72](https://github.com/cloud-copilot/iam-lens/compare/v0.1.71...v0.1.72) (2025-12-20)

## [0.1.71](https://github.com/cloud-copilot/iam-lens/compare/v0.1.70...v0.1.71) (2025-12-13)

## [0.1.70](https://github.com/cloud-copilot/iam-lens/compare/v0.1.69...v0.1.70) (2025-12-09)


### Bug Fixes

* Correctly set bucket tags for s3 objects ([dfde5bf](https://github.com/cloud-copilot/iam-lens/commit/dfde5bf96bd3cddfe68382ab3228fe0bbd654813))

## [0.1.69](https://github.com/cloud-copilot/iam-lens/compare/v0.1.68...v0.1.69) (2025-12-08)


### Features

* Add optional sorting of who-can results ([d2e381e](https://github.com/cloud-copilot/iam-lens/commit/d2e381eb7d6fea19bd293b71120fff1707d05a78))

## [0.1.68](https://github.com/cloud-copilot/iam-lens/compare/v0.1.67...v0.1.68) (2025-12-08)


### Features

* S3 ABAC support with optional overrides ([ec08fd7](https://github.com/cloud-copilot/iam-lens/commit/ec08fd752da0858d24add968c4b7d87e1b0761e3))

## [0.1.67](https://github.com/cloud-copilot/iam-lens/compare/v0.1.66...v0.1.67) (2025-12-06)

## [0.1.66](https://github.com/cloud-copilot/iam-lens/compare/v0.1.65...v0.1.66) (2025-11-30)


### Bug Fixes

* Fix principal-cans handling of Allow statements with Resource being combined with Deny statements that have NotResource ([70d8e53](https://github.com/cloud-copilot/iam-lens/commit/70d8e53903c6be7bd023d8bab91f3608e1cfe019))

## [0.1.65](https://github.com/cloud-copilot/iam-lens/compare/v0.1.64...v0.1.65) (2025-11-30)

## [0.1.64](https://github.com/cloud-copilot/iam-lens/compare/v0.1.63...v0.1.64) (2025-11-24)


### Bug Fixes

* Add permission boundary deny statements to principal-can ([a780070](https://github.com/cloud-copilot/iam-lens/commit/a780070203571e1a017eb3de37c7637743764b64))

## [0.1.63](https://github.com/cloud-copilot/iam-lens/compare/v0.1.62...v0.1.63) (2025-11-23)


### Bug Fixes

* Fix error in handling Allow Resource wildcard and Deny NotResource subset ([a48eb3f](https://github.com/cloud-copilot/iam-lens/commit/a48eb3f13834d2a6368d8be0e4d38e6b031e5a30))

## [0.1.62](https://github.com/cloud-copilot/iam-lens/compare/v0.1.61...v0.1.62) (2025-11-23)


### Features

* Add support and automatic population for aws:SourceVpcArn ([461745a](https://github.com/cloud-copilot/iam-lens/commit/461745a1642b91e80eab1afb97ecd865cfcdaf99))

## [0.1.61](https://github.com/cloud-copilot/iam-lens/compare/v0.1.60...v0.1.61) (2025-11-22)

## [0.1.60](https://github.com/cloud-copilot/iam-lens/compare/v0.1.59...v0.1.60) (2025-11-21)

## [0.1.59](https://github.com/cloud-copilot/iam-lens/compare/v0.1.58...v0.1.59) (2025-11-15)

## [0.1.58](https://github.com/cloud-copilot/iam-lens/compare/v0.1.57...v0.1.58) (2025-11-11)

## [0.1.57](https://github.com/cloud-copilot/iam-lens/compare/v0.1.56...v0.1.57) (2025-11-08)

## [0.1.56](https://github.com/cloud-copilot/iam-lens/compare/v0.1.55...v0.1.56) (2025-11-01)

## [0.1.55](https://github.com/cloud-copilot/iam-lens/compare/v0.1.54...v0.1.55) (2025-10-29)


### Features

* Smaller principal indexes ([412de8f](https://github.com/cloud-copilot/iam-lens/commit/412de8f44bb9063ceaae9539a40987240306e681))

## [0.1.54](https://github.com/cloud-copilot/iam-lens/compare/v0.1.53...v0.1.54) (2025-10-25)

## [0.1.53](https://github.com/cloud-copilot/iam-lens/compare/v0.1.52...v0.1.53) (2025-10-18)

## [0.1.52](https://github.com/cloud-copilot/iam-lens/compare/v0.1.51...v0.1.52) (2025-10-15)


### Bug Fixes

* Properly separate Deny statements with multiple conditions into multiple Allow statements ([ad3b269](https://github.com/cloud-copilot/iam-lens/commit/ad3b26972c49d1e4dbed220137cda4503eb92ef0))


### Features

* `principal-can`to incorporate trust policies in the same account. ([b47c298](https://github.com/cloud-copilot/iam-lens/commit/b47c298b799a654350ed5301266a69553e91d3f6))

## [0.1.51](https://github.com/cloud-copilot/iam-lens/compare/v0.1.50...v0.1.51) (2025-10-14)

## [0.1.50](https://github.com/cloud-copilot/iam-lens/compare/v0.1.49...v0.1.50) (2025-10-13)


### Features

* `principal-can` evaluate same account KMS key policies ([4a56373](https://github.com/cloud-copilot/iam-lens/commit/4a56373bb0c2fef9789aec517731d16b838074a0))

## [0.1.49](https://github.com/cloud-copilot/iam-lens/compare/v0.1.48...v0.1.49) (2025-10-11)

## [0.1.48](https://github.com/cloud-copilot/iam-lens/compare/v0.1.47...v0.1.48) (2025-10-11)

## [0.1.47](https://github.com/cloud-copilot/iam-lens/compare/v0.1.46...v0.1.47) (2025-10-07)

## [0.1.46](https://github.com/cloud-copilot/iam-lens/compare/v0.1.45...v0.1.46) (2025-10-05)

## [0.1.45](https://github.com/cloud-copilot/iam-lens/compare/v0.1.44...v0.1.45) (2025-10-05)


### Features

* Document principal-can. Add support for S3 bucket resource policies in the same account. ([f746027](https://github.com/cloud-copilot/iam-lens/commit/f7460271488267232da9eb8d295e0c87cd509a77))

## [0.1.44](https://github.com/cloud-copilot/iam-lens/compare/v0.1.43...v0.1.44) (2025-10-04)

## [0.1.43](https://github.com/cloud-copilot/iam-lens/compare/v0.1.42...v0.1.43) (2025-10-04)

## [0.1.42](https://github.com/cloud-copilot/iam-lens/compare/v0.1.41...v0.1.42) (2025-09-28)

## [0.1.41](https://github.com/cloud-copilot/iam-lens/compare/v0.1.40...v0.1.41) (2025-09-20)

## [0.1.40](https://github.com/cloud-copilot/iam-lens/compare/v0.1.39...v0.1.40) (2025-09-15)

## [0.1.39](https://github.com/cloud-copilot/iam-lens/compare/v0.1.38...v0.1.39) (2025-09-07)

## [0.1.38](https://github.com/cloud-copilot/iam-lens/compare/v0.1.37...v0.1.38) (2025-09-04)


### Features

* who-can performance improvements ([ed70dec](https://github.com/cloud-copilot/iam-lens/commit/ed70dec7557718abc1fef7c455fd5fcb332042e0))

## [0.1.37](https://github.com/cloud-copilot/iam-lens/compare/v0.1.36...v0.1.37) (2025-09-01)

## [0.1.36](https://github.com/cloud-copilot/iam-lens/compare/v0.1.35...v0.1.36) (2025-08-30)


### Features

* Automatically set aws:VpceAccount, aws:VpceOrgID, and aws:VpceOrgPaths for supported services when a VPC endpoint is specified. ([1d56a13](https://github.com/cloud-copilot/iam-lens/commit/1d56a136abbf6da372442fd543419d94640c81c5))

## [0.1.35](https://github.com/cloud-copilot/iam-lens/compare/v0.1.34...v0.1.35) (2025-08-25)


### Features

* Upgrade iam-data ([1039dac](https://github.com/cloud-copilot/iam-lens/commit/1039dac8899055d39296e2290c4f638807e92b50))

## [0.1.34](https://github.com/cloud-copilot/iam-lens/compare/v0.1.33...v0.1.34) (2025-08-22)


### Features

* Improve ux for custom context keys ([2cb9aa8](https://github.com/cloud-copilot/iam-lens/commit/2cb9aa872922f8192283db8b87964410a83b27a7))

## [0.1.33](https://github.com/cloud-copilot/iam-lens/compare/v0.1.32...v0.1.33) (2025-08-22)

## [0.1.32](https://github.com/cloud-copilot/iam-lens/compare/v0.1.31...v0.1.32) (2025-08-16)

## [0.1.31](https://github.com/cloud-copilot/iam-lens/compare/v0.1.30...v0.1.31) (2025-08-09)

## [0.1.30](https://github.com/cloud-copilot/iam-lens/compare/v0.1.29...v0.1.30) (2025-08-03)

## [0.1.29](https://github.com/cloud-copilot/iam-lens/compare/v0.1.28...v0.1.29) (2025-07-30)


### Bug Fixes

* Use S3 bucket policy when testing for S3 objects ([7b6ff2e](https://github.com/cloud-copilot/iam-lens/commit/7b6ff2ec1be0ffd99d8d1cb9d4c4d54d61cd12f3))

## [0.1.28](https://github.com/cloud-copilot/iam-lens/compare/v0.1.27...v0.1.28) (2025-07-26)

## [0.1.27](https://github.com/cloud-copilot/iam-lens/compare/v0.1.26...v0.1.27) (2025-07-23)


### Features

* Export functions with supporting interfaces and classes. ([3a30c0b](https://github.com/cloud-copilot/iam-lens/commit/3a30c0b472431e2f2dbf1241472de3bb45ce7f07))

## [0.1.26](https://github.com/cloud-copilot/iam-lens/compare/v0.1.25...v0.1.26) (2025-07-23)


### Features

* Improved performance for who-can. Improved handling of context keys. Ensure principal exists before running a simulate command. ([c4a5a87](https://github.com/cloud-copilot/iam-lens/commit/c4a5a87bc91570dc26a77c4dcf53b20127c95b8c))

## [0.1.25](https://github.com/cloud-copilot/iam-lens/compare/v0.1.24...v0.1.25) (2025-07-12)

## [0.1.24](https://github.com/cloud-copilot/iam-lens/compare/v0.1.23...v0.1.24) (2025-07-02)


### Features

* Add support for loading and evaluating vpc endpoint policies ([2169fc5](https://github.com/cloud-copilot/iam-lens/commit/2169fc5e4628f37087bb39e53520eb1d9bde2f3a))

## [0.1.23](https://github.com/cloud-copilot/iam-lens/compare/v0.1.22...v0.1.23) (2025-06-29)

## [0.1.22](https://github.com/cloud-copilot/iam-lens/compare/v0.1.21...v0.1.22) (2025-06-28)


### Features

* changing can-what to principal-can ([cd217f8](https://github.com/cloud-copilot/iam-lens/commit/cd217f8674fb405f5ac6a0782beb8193c17a3895))
* improve handling of tag keys in simulate ([5315d30](https://github.com/cloud-copilot/iam-lens/commit/5315d307bf6575961d864d9c97cee6bfb7086d08))
* Improve performance of who-can ([4d1ada6](https://github.com/cloud-copilot/iam-lens/commit/4d1ada64c34fc2a51abff8cab97f863922ac888f))
* improved caching of policies ([0b82808](https://github.com/cloud-copilot/iam-lens/commit/0b828085fdd75dfdaa656bb64ddb9f97cfad58d5))

## [0.1.21](https://github.com/cloud-copilot/iam-lens/compare/v0.1.20...v0.1.21) (2025-06-22)


### Bug Fixes

* Add missing parameter for simulate call ([f5e0f62](https://github.com/cloud-copilot/iam-lens/commit/f5e0f62d252e3faafc1f3099a597ffdff5fa3c46))


### Features

* Add access level to the output of who-can ([4bbaaf1](https://github.com/cloud-copilot/iam-lens/commit/4bbaaf1df3ef4a3cbcd9a72d1d991070da49f53e))
* Add condition reporting to who-can along with access level ([3811980](https://github.com/cloud-copilot/iam-lens/commit/3811980257c14da90324416fcff0551c4dcf990b))

## [0.1.20](https://github.com/cloud-copilot/iam-lens/compare/v0.1.19...v0.1.20) (2025-06-21)

## [0.1.19](https://github.com/cloud-copilot/iam-lens/compare/v0.1.18...v0.1.19) (2025-06-16)

## [0.1.18](https://github.com/cloud-copilot/iam-lens/compare/v0.1.17...v0.1.18) (2025-06-15)


### Bug Fixes

* Fix simulating actions with AWS managed policies ([31566a9](https://github.com/cloud-copilot/iam-lens/commit/31566a9a791d0fea7e1000d24ea0e5401309f732))

## [0.1.17](https://github.com/cloud-copilot/iam-lens/compare/v0.1.16...v0.1.17) (2025-06-14)

## [0.1.16](https://github.com/cloud-copilot/iam-lens/compare/v0.1.15...v0.1.16) (2025-06-13)

## [0.1.15](https://github.com/cloud-copilot/iam-lens/compare/v0.1.14...v0.1.15) (2025-06-13)


### Bug Fixes

* Properly get account id for AWS managed policies ([72603b0](https://github.com/cloud-copilot/iam-lens/commit/72603b03efe9d069abbe2513bb7af2169c9002d6))

## [0.1.14](https://github.com/cloud-copilot/iam-lens/compare/v0.1.13...v0.1.14) (2025-06-13)

## [0.1.13](https://github.com/cloud-copilot/iam-lens/compare/v0.1.12...v0.1.13) (2025-06-12)


### Features

* Initial implementation of can-what ([eed7c3a](https://github.com/cloud-copilot/iam-lens/commit/eed7c3ac4cb1c84801a2f09d5692a3b469c32b24))

## [0.1.12](https://github.com/cloud-copilot/iam-lens/compare/v0.1.11...v0.1.12) (2025-06-11)

## [0.1.11](https://github.com/cloud-copilot/iam-lens/compare/v0.1.10...v0.1.11) (2025-06-07)

## [0.1.10](https://github.com/cloud-copilot/iam-lens/compare/v0.1.9...v0.1.10) (2025-06-02)

## [0.1.9](https://github.com/cloud-copilot/iam-lens/compare/v0.1.8...v0.1.9) (2025-06-01)

## [0.1.8](https://github.com/cloud-copilot/iam-lens/compare/v0.1.7...v0.1.8) (2025-06-01)


### Features

* Add caching of SCPs and RCPs for multiple simulations ([0b314a4](https://github.com/cloud-copilot/iam-lens/commit/0b314a4390015e58c92511b2652b8be98fd31fe8))

## [0.1.7](https://github.com/cloud-copilot/iam-lens/compare/v0.1.6...v0.1.7) (2025-05-27)


### Features

* Add version as a cli option ([e67e410](https://github.com/cloud-copilot/iam-lens/commit/e67e41009ad556e2a0c4bcd2a2392644ca2f02d8))
* Don't use role trust policies for iam actions. ([a0d663e](https://github.com/cloud-copilot/iam-lens/commit/a0d663ed27c12d3dc964ab9b22e3611da1c35e0f))

## [0.1.6](https://github.com/cloud-copilot/iam-lens/compare/v0.1.5...v0.1.6) (2025-05-27)


### Bug Fixes

* Fix path for importing role trust policies. ([92c58cb](https://github.com/cloud-copilot/iam-lens/commit/92c58cbc8fe9c6a645eefbcd279bce8d50c78d9e))


### Features

* Add check for trust policy for all STS assume role actions. ([f9cfe32](https://github.com/cloud-copilot/iam-lens/commit/f9cfe321d86acdebb103fd1853b074ce63024ca6))

## [0.1.5](https://github.com/cloud-copilot/iam-lens/compare/v0.1.4...v0.1.5) (2025-05-26)

## [0.1.4](https://github.com/cloud-copilot/iam-lens/compare/v0.1.3...v0.1.4) (2025-05-26)


### Features

* Simulate requests on the CLI ([4644814](https://github.com/cloud-copilot/iam-lens/commit/4644814d3295e31cd7247a0622fe75362f4ed30c))

## [0.1.3](https://github.com/cloud-copilot/iam-lens/compare/v0.1.2...v0.1.3) (2025-05-24)

## [0.1.2](https://github.com/cloud-copilot/iam-lens/compare/v0.1.1...v0.1.2) (2025-05-23)


### Features

* Add new functions to get policy information for resources and principals ([3a8989f](https://github.com/cloud-copilot/iam-lens/commit/3a8989f482c542f55a955f4128d413426e6f24d3))

## [0.1.1](https://github.com/cloud-copilot/iam-lens/compare/v0.1.0...v0.1.1) (2025-05-17)
