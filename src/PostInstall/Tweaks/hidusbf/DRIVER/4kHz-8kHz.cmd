pushd "%~dp0"
copy /V /Y "%~dp0NTX86\4kHz-8kHz\hidusbf.sys" "%~dp0NTX86\"
copy /V /Y "%~dp0AMD64\4kHz-8kHz\hidusbf.sys" "%~dp0AMD64\"
copy /V /Y "%~dp0NTX86_AS\4kHz-8kHz\hidusbf.sys" "%~dp0NTX86_AS\"
copy /V /Y "%~dp0AMD64_AS\4kHz-8kHz\hidusbf.sys" "%~dp0AMD64_AS\"
popd