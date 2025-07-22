cat >dist/cjs/package.json <<!EOF
{
    "type": "commonjs"
}
!EOF
rm -rf dist/cjs/utils/readPackageFileEsm.*
rm -rf dist/cjs/utils/workerScriptEsm.*

cat >dist/esm/package.json <<!EOF
{
    "type": "module"
}
!EOF
mv dist/esm/utils/readPackageFileEsm.js dist/esm/utils/readPackageFile.js
mv dist/esm/utils/readPackageFileEsm.d.ts dist/esm/utils/readPackageFile.d.ts
mv dist/esm/utils/readPackageFileEsm.js.map dist/esm/utils/readPackageFile.js.map

mv dist/esm/utils/workerScriptEsm.js dist/esm/utils/workerScript.js
mv dist/esm/utils/workerScriptEsm.d.ts dist/esm/utils/workerScript.d.ts
mv dist/esm/utils/workerScriptEsm.js.map dist/esm/utils/workerScript.js.map