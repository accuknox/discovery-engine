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

# switch to master
git checkout master

# merge upstream/master
git merge upstream/master

# push to my repo
git push origin master
