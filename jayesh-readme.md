```

cd my-projects/github/kubernetes/opensource/website-jayesh/website
git fetch --all
BRANCH=jm/hi-example-guestbook
git checkout upstream/main
git checkout -b $BRANCH upstream/main


git push origin $BRANCH

#squash  
#git rev-list --count $BRANCH --not upstream/main
NUMBER_OF_COMMITS=`git rev-list --count $BRANCH --not upstream/main`

#git rebase -i upstream/main~24
#git rebase -i upstream/main~$NUMBER_OF_COMMITS

```


From: dockerfile
```
RUN mkdir $HOME/src && \
    cd $HOME/src && \
    curl -L https://github.com/gohugoio/hugo/archive/refs/tags/v${HUGO_VERSION}.tar.gz | tar -xz && \
    cd "hugo-${HUGO_VERSION}" && \
    go install --tags extended
```
To:

dockerfile
```
RUN mkdir -p $HOME/src && \
    cd $HOME/src && \
    curl -L -o hugo_extended.tar.gz https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz && \
    tar -xzf hugo_extended.tar.gz && \
    mv hugo /go/bin/hugo
```
local follow https://kubernetes.io/docs/contribute/new-content/open-a-pr/#preview-locally
