```

cd my-projects/github/kubernetes/opensource/website-jayesh/website
git fetch --all
BRANCH=jm/hi-example-guestbook
git checkout upstream/main
git checkout -b $BRANCH upstream/main

npm ci
make serve

git push origin $BRANCH

#squash  
#git rev-list --count $BRANCH --not upstream/main
NUMBER_OF_COMMITS=`git rev-list --count $BRANCH --not upstream/main`

#git rebase -i upstream/main~24
#git rebase -i upstream/main~$NUMBER_OF_COMMITS

```


local follow https://kubernetes.io/docs/contribute/new-content/open-a-pr/#preview-locally


<!--
 Hello!

 PLEASE title the FIRST commit appropriately, so that if you squash all
 your commits into one, the combined commit message makes sense.
 For overall help on editing and submitting pull requests, visit:
  https://kubernetes.io/docs/contribute/suggesting-improvements/

 Use the default base branch, “main”, if you're documenting existing
 features in the English localization.

 If you're working on a different localization (not English), see
 https://kubernetes.io/docs/contribute/new-content/overview/#choose-which-git-branch-to-use
 for advice.

 If you're documenting a feature that will be part of a future release, see
 https://kubernetes.io/docs/contribute/new-content/new-features/ for advice.
-->

### Description
Lot of example content thats referred as yaml are missing in Hindi content.
e.g. https://github.com/kubernetes/website/tree/main/content/en/examples/pods are not similar to
https://github.com/kubernetes/website/tree/main/content/hi/examples
This has dependency on lot of other content translation.

All examples from https://github.com/kubernetes/website/tree/main/content/en/examples/pods need to be added here
https://github.com/kubernetes/website/tree/main/content/hi/examples

<!--
 Remember to ADD A DESCRIPTION and delete this note before submitting
 your pull request. The description should explain what will change,
 and why.
-->

### Issue
 https://github.com/kubernetes/website/issues/50716

<!--
 If this pull request resolves an open issue, please link the issue in the PR
 description so it will automatically close when the PR is merged.

 See the GitHub documentation for more details and other options:

 https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue-using-a-keyword
-->

Closes:
