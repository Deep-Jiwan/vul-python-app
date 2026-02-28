param(
    [Parameter(Position=0)]
    [string]$CommitMessage
)

git status
git add .

if ([string]::IsNullOrWhiteSpace($CommitMessage)) {
    $input = Read-Host 'Enter commit message (press Enter for "Auto commit")'
    if ([string]::IsNullOrWhiteSpace($input)) {
        $CommitMessage = "Auto commit"
    } else {
        $CommitMessage = $input
    }
}

git commit -m $CommitMessage
git push -u origin main