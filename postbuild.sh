cat >dist/cjs/package.json <<!EOF
{
    "type": "commonjs"
}
!EOF
rm -rf dist/cjs/utils/readPackageFileEsm.*

cat >dist/esm/package.json <<!EOF
{
    "type": "module"
}
!EOF
mv dist/esm/utils/readPackageFileEsm.js dist/esm/utils/readPackageFile.js
mv dist/esm/utils/readPackageFileEsm.d.ts dist/esm/utils/readPackageFile.d.ts
mv dist/esm/utils/readPackageFileEsm.js.map dist/esm/utils/readPackageFile.js.map