# Integration Guide

## Local

```sh
refraction --min-severity warning --min-confidence medium .
refraction --format json --pretty --output-file refraction.json .
```

## GitHub Actions

```yaml
name: refraction
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - run: go run ./cmd/refraction --format github --min-severity warning --min-confidence medium .
```

## GitLab CI

```yaml
refraction:
  image: golang:1.22
  script:
    - go run ./cmd/refraction --format sarif --output-file refraction.sarif .
  artifacts:
    when: always
    paths: [refraction.sarif]
```

## CircleCI

```yaml
version: 2.1
jobs:
  refraction:
    docker:
      - image: cimg/go:1.22
    steps:
      - checkout
      - run: go run ./cmd/refraction --min-severity warning --min-confidence medium .
```

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('refraction') {
      steps {
        sh 'go run ./cmd/refraction --format json --output-file refraction.json .'
        archiveArtifacts artifacts: 'refraction.json', allowEmptyArchive: true
      }
    }
  }
}
```

## pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: refraction
        name: refraction
        entry: refraction --min-severity warning --min-confidence medium
        language: system
        pass_filenames: false
```

## Makefile

```make
.PHONY: refraction
refraction:
	refraction --min-severity warning --min-confidence medium .
```
