param(
  [string]$Ref = "main"
)

if (!(Test-Path "vendor/open-webui")) {
  git clone --depth 1 --branch $Ref https://github.com/open-webui/open-webui.git vendor/open-webui
} else {
  git -C vendor/open-webui fetch origin $Ref --depth 1
  git -C vendor/open-webui checkout $Ref
  git -C vendor/open-webui pull --ff-only origin $Ref
}

Write-Host "Open WebUI synced to $Ref"
Write-Host "Re-apply Superhuman constants patch if upstream changed src/lib/constants.ts"
