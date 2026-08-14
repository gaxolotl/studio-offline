ALWAYS build via GitHub Actions, never locally.
Run: gh workflow run build.yml --repo gaxolotl/studio-offline
Watch: gh run watch <id> --repo gaxolotl/studio-offline --exit-status
Download: gh run download <id> --repo gaxolotl/studio-offline --dir <dest>
Reason: the local machine (ThinkPad) is not powerful enough for cargo builds.
Deploy: copy studio_offline_server.exe to C:\Users\Georgi\Desktop\studio-offline-server\

ALWAYS tell the user when they can help make work faster: installing tools, preparing test places/scripts in Studio, starting/stopping the server, pasting console logs.

