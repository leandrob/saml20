@Library('jenkinsfile-shared-library') _

node {
	stage ('Checkout'){
		checkout scm
	}
	nvm(getNodeVersion()) {
		codeReview((String[]) ["withoutDependenciesSetup", "withoutCoverage"])
		codeVersion()
		codePublishNPM()
	}
}