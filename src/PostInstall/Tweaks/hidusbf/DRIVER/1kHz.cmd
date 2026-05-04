pushd "%~dp0"
copy /V /Y "%~dp0NTX86\1kHz\hidusbf.sys" "%~dp0NTX86\"
copy /V /Y "%~dp0AMD64\1kHz\hidusbf.sys" "%~dp0AMD64\"
copy /V /Y "%~dp0NTX86_AS\1kHz\hidusbf.sys" "%~dp0NTX86_AS\"
copy /V /Y "%~dp0AMD64_AS\1kHz\hidusbf.sys" "%~dp0AMD64_AS\"
popd