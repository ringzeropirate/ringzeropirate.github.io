https://ringzeropirate.github.io

git filter-branch -f --env-filter '
OLD_EMAIL="m.piccinni@OCTO-Lap332.octo.local"
CORRECT_NAME="ringzeropirate"
CORRECT_EMAIL="ringzeropirate@proton.me"

if [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL" ]
then
    export GIT_COMMITTER_NAME="$CORRECT_NAME"
    export GIT_COMMITTER_EMAIL="$CORRECT_EMAIL"
fi
if [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL" ]
then
    export GIT_AUTHOR_NAME="$CORRECT_NAME"
    export GIT_AUTHOR_EMAIL="$CORRECT_EMAIL"
fi
' --tag-name-filter cat -- --branches --tags