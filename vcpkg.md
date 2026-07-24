# Build with vcpkg

- install vcpkg
- Create `CMakeUserPresets.json` with the command 

```sh
cat <<EOF | tee CMakeUserPresets.json
{
  "version": 2,
  "configurePresets": [
    {
      "name": "default",
      "inherits": "vcpkg",
      "environment": {
        "VCPKG_ROOT": "${VCPKG_ROOT}"
      }
    }
  ]
}
EOF
```

- Run `rm -fr build; cmake --preset=default; cmake -S. -Bbuild -DCMAKE_BUILD_TYPE=MinSizeRel; cmake --build build` for the build with vcpkg
- Run `rm -fr build; cmake -S. -Bbuild -DCMAKE_BUILD_TYPE=MinSizeRel; cmake --build build` for the build without vcpkg