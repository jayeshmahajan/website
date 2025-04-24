```

cd my-projects/github/kubernetes/opensource/website-jayesh/website
git fetch --all
BRANCH=jm/hi-example-guestbook
git checkout -b $BRANCH upstream/main


git push origin $BRANCH

#squash  
#git rev-list --count $BRANCH --not upstream/main
NUMBER_OF_COMMITS=`git rev-list --count $BRANCH --not upstream/main`

#git rebase -i upstream/main~24
#git rebase -i upstream/main~$NUMBER_OF_COMMITS

```
