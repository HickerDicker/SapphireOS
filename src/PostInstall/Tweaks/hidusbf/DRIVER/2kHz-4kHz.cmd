pushd "%~dp0"
copy /V /Y "%~dp0NTX86\2kHz-4kHz\hidusbf.sys" "%~dp0NTX86\"
copy /V /Y "%~dp0AMD64\2kHz-4kHz\hidusbf.sys" "%~dp0AMD64\"
popd
