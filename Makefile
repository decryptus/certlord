#!/usr/bin/make -f
# -*- makefile -*-

CHANGELOG_PATH ?= "$(CURDIR)/CHANGELOG"
DCH_PATH ?= dch
DPKG_PARSECHANGELOG_PATH ?= dpkg-parsechangelog
EDITOR_PATH ?= vim
FIND_PATH ?= find
GIT_PATH ?= git
GREP_PATH ?= grep
J2_PATH ?= j2
MAKE_PATH ?= make
PYTHON2_PATH ?= python2
PYTHON3_PATH ?= python3
RM_PATH ?= rm
SED_PATH ?= sed
TWINE_PATH ?= twine

export PROJECT_RELEASE=$(shell $(DPKG_PARSECHANGELOG_PATH) -S Version -l $(CHANGELOG_PATH))
export PROJECT_VERSION=$(shell $(DPKG_PARSECHANGELOG_PATH) -S Version -l $(CHANGELOG_PATH) | $(SED_PATH) 's/~//g')
export PROJECT_GIT_RELEASE="$(shell echo -n "$(PROJECT_RELEASE)"| $(SED_PATH) 's/~//g')"
export PROJECT_COPYRIGHT_YEAR=$(shell date +'%Y')

changelog:
	EDITOR="$(EDITOR_PATH)" $(DCH_PATH) -i -D unstable --no-auto-nmu -m --changelog "$(CHANGELOG_PATH)"
	$(MAKE_PATH) release
	$(MAKE_PATH) version

release:
	$(shell echo $(PROJECT_VERSION) > "$(CURDIR)/RELEASE")

version:
	$(shell echo $(PROJECT_VERSION) > "$(CURDIR)/VERSION")

setup-config:
	$(MAKE_PATH) release
	$(MAKE_PATH) version
	$(J2_PATH) setup.yml.j2 -o setup.yml

build-git-commit:
	$(DPKG_PARSECHANGELOG_PATH) -S Changes -l "$(CHANGELOG_PATH)"|\
        $(GREP_PATH) '^\s\+\*'|\
        $(SED_PATH) -e 's/^\s\+\*\s\(.\+\)$$/\1/'|\
        $(GIT_PATH) commit -a -F - || true

build-git-version:
	if [ -d "bin" ]; then \
    	$(FIND_PATH) bin/ -type f | while read file; \
    	do \
        	$(SED_PATH) -i -e "s/^\(__version__\s*=\s*\)['\"]\(.*\)['\"]/\1'${PROJECT_VERSION}'/" "$$file"; \
    	done \
	fi ;

push-git-version:
	$(GIT_PATH) push
	$(GIT_PATH) tag -a "v$(PROJECT_VERSION)" -m "version: $(PROJECT_VERSION)"
	$(GIT_PATH) push origin "v$(PROJECT_VERSION)"

push-git-release:
	$(GIT_PATH) push
	$(GIT_PATH) tag -a "$(PROJECT_GIT_RELEASE)-release" -m "release: $(PROJECT_GIT_RELEASE)"
	$(GIT_PATH) push origin "$(PROJECT_GIT_RELEASE)-release"

git-push:
	$(MAKE_PATH) changelog
	$(MAKE_PATH) setup-config
	$(MAKE_PATH) build-git-version
	$(MAKE_PATH) build-git-commit

git-version:
	$(MAKE_PATH) git-push
	$(MAKE_PATH) push-git-version

git-release:
	$(MAKE_PATH) git-push
	$(MAKE_PATH) push-git-release

clean-python:
	$(FIND_PATH) -type f -name "*.pyc" -delete
	$(FIND_PATH) -type d -name __pycache__ -exec rm -rf '{}' +

clean: clean-python

.PHONY: changelog release version
