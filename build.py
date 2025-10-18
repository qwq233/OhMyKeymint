#!/usr/bin/env python3
"""
Build script for OhMyKeymint Android targets
"""

import argparse
import os
import shutil
import subprocess
import hashlib
import zipfile
import toml
import subprocess
import glob

def get_version_from_cargo_toml():
    """Read version from Cargo.toml"""
    with open('./Cargo.toml', 'r') as f:
        cargo_toml = toml.load(f)
        return cargo_toml['package']['version']

def get_git_commit_count():
    """Get git commit count - must be numeric only"""
    result = subprocess.run(['git', 'rev-list', '--count', 'HEAD'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        git_count = result.stdout.strip()
        # Validate that git_count contains only digits
        if not git_count.isdigit():
            raise ValueError(f"Git commit count must be numeric only, got: {git_count}")
        return git_count
    raise Exception("Failed to get git commit count")

def get_git_commit_hash():
    """Get git commit hash (first 7 characters)"""
    result = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        full_hash = result.stdout.strip()
        return full_hash[:7]  # Return first 7 characters
    raise Exception("Failed to get git commit hash")

def build_target(target, release=False):
    """Build for specific target"""
    build_type = "release" if release else "debug"
    print(f"Building for {target} ({build_type})...")
    
    cmd = ['cargo', 'ndk', '-t', target, '-o', 'build', 'build']
    if release:
        cmd.append('--release')
    
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise Exception(f"Build failed for {target}")

def copy_binary(target, arch_name, release=False):
    """Copy built binary from correct target directory"""
    build_type = "release" if release else "debug"
    source_path = f"target/{target}/{build_type}/keymint"
    
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Binary not found at {source_path}")
    
    dest_dir = f"target/temp/libs/{arch_name}"
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy2(source_path, f"{dest_dir}/keymint")
    print(f"Copied binary from {source_path} to {dest_dir}/keymint")

def copy_template_files():
    """Copy template directory contents to temp folder"""
    temp_dir = "target/temp"
    template_dir = "template"
    
    if not os.path.exists(template_dir):
        raise FileNotFoundError("Template directory not found")
    
    print("Copying template files...")
    for item in os.listdir(template_dir):
        src = os.path.join(template_dir, item)
        dst = os.path.join(temp_dir, item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)

def modify_module_prop(version, git_count, git_hash):
    """Modify module.prop file with version, git count and git hash"""
    module_prop_path = "target/temp/module.prop"
    
    if not os.path.exists(module_prop_path):
        raise FileNotFoundError(f"module.prop not found at {module_prop_path}")
    
    print("Modifying module.prop file...")
    
    with open(module_prop_path, 'r') as f:
        content = f.read()
    
    # Create version name with git hash
    version_name = f"{version}-{git_hash}"
    
    # Replace placeholders
    content = content.replace("${versionName}", version_name)
    content = content.replace("${versionCode}", git_count)
    
    with open(module_prop_path, 'w') as f:
        f.write(content)
    
    print(f"Updated module.prop: versionName={version_name}, versionCode={git_count}")

def generate_hash_for_file(file_path):
    """Generate SHA256 hash for a single file"""
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    hash_file = f"{file_path}.sha256"
    with open(hash_file, 'w') as f:
        f.write(file_hash)
    print(f"Created hash file: {hash_file}")

def generate_hash_files():
    """Generate SHA256 hash files for root directory files and binaries"""
    temp_dir = "target/temp"
    
    print("Generating SHA256 hash files...")
    
    # Generate hash files for root directory files
    for item in os.listdir(temp_dir):
        item_path = os.path.join(temp_dir, item)
        if os.path.isfile(item_path):
            generate_hash_for_file(item_path)
    
    # Generate hash files for binaries in libs directory
    libs_dir = os.path.join(temp_dir, "libs")
    if os.path.exists(libs_dir):
        for arch_dir in os.listdir(libs_dir):
            arch_path = os.path.join(libs_dir, arch_dir)
            if os.path.isdir(arch_path):
                for binary in os.listdir(arch_path):
                    binary_path = os.path.join(arch_path, binary)
                    if os.path.isfile(binary_path):
                        generate_hash_for_file(binary_path)

def delete_old_zips(release=False):
    """Delete all old zip files with the same build type"""
    build_type = "release" if release else "debug"
    pattern = f"target/OhMyKeymint-{build_type}-*.zip"
    
    old_zips = glob.glob(pattern)
    if old_zips:
        print(f"Found {len(old_zips)} old zip file(s) to delete:")
        for old_zip in old_zips:
            print(f"  Deleting: {old_zip}")
            os.remove(old_zip)
    else:
        print(f"No old zip files found matching pattern: {pattern}")

def create_zip_package(version, git_hash, release=False):
    """Create final zip package"""
    build_type = "release" if release else "debug"
    zip_name = f"target/OhMyKeymint-{build_type}-{version}-{git_hash}.zip"
    
    print(f"Creating zip package: {zip_name}")
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk("target/temp"):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, "target/temp")
                zipf.write(file_path, arcname)
    
    return zip_name

def main():
    parser = argparse.ArgumentParser(description='Build OhMyKeymint for Android')
    parser.add_argument('--release', action='store_true', 
                       help='Build in release mode')
    parser.add_argument('--debug', action='store_true', 
                       help='Build in debug mode (default)')
    args = parser.parse_args()

    # Clean up previous temp directory
    if os.path.exists("target/temp"):
        shutil.rmtree("target/temp")

    # Create target directory structure
    os.makedirs("target/temp", exist_ok=True)

    try:
        # Get version and git info
        version = get_version_from_cargo_toml()
        git_count = get_git_commit_count()
        git_hash = get_git_commit_hash()
        
        print(f"Building OhMyKeymint version {version} (commit {git_count}, hash {git_hash})")
        print(f"Build mode: {'Release' if args.release else 'Debug'}")

        # Delete all old zip files with the same build type
        delete_old_zips(args.release)

        # Build targets
        targets = [
            ("aarch64-linux-android", "arm64-v8a"),
            # ("x86_64-linux-android", "x86_64")
        ]

        for target, arch_name in targets:
            build_target(target, args.release)
            copy_binary(target, arch_name, args.release)

        # Copy template files
        copy_template_files()

        # Modify module.prop file
        modify_module_prop(version, git_count, git_hash)

        # Generate hash files for all files including binaries
        generate_hash_files()

        # Create final zip
        zip_path = create_zip_package(version, git_hash, args.release)
        
        print(f"Build completed successfully!")
        print(f"Output: {zip_path}")

    except Exception as e:
        print(f"Build failed: {e}")
        # Clean up on failure
        if os.path.exists("target/temp"):
            shutil.rmtree("target/temp")
        exit(1)

if __name__ == "__main__":
    main()

