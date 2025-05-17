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
