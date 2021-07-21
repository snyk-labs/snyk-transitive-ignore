
## snyk-transitive-ignore
proof of concept to ignore all issues (direct or transitive) brought by a particular dependency

## Installation
clone this repo, and then run `npm install -g`

## Usage
1. add your package names to your file, for example `packages-to-ignore.list` (see example [here](https://github.com/snyk-tech-services/snyk-transitive-ignore/blob/master/fixtures/sample-packages-to-ignore.list))
2. run `snyk test --json | snyk-transitive-ignore -f packages-to-ignore.list` to generate the ignore list dynamically (into `.snyk_ignore` file)
3. run `snyk test --policy-path=.snyk_ignore` to test again with the Snyk ignore policy in place