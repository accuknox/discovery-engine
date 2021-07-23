#!/bin/bash

KNOX_HOME=`dirname $(realpath "$0")`/..
cd $KNOX_HOME

# add upstream if it doesn't exist
git remote -v | grep accuknox
if [ $? != 0 ]; then
	git remote add upstream https://github.com/accuknox/knoxAutoPolicy.git
fi

# fetch upstream
git fetch upstream

# switch to dev
git checkout dev

# merge upstream/master
git merge upstream/dev

# push to my repo
git push origin dev
