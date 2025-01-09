#!/bin/bash

# Define the image folder and the root of your project
IMAGE_FOLDER="./src/images"
PROJECT_ROOT="."

# Move to the project root
cd "$PROJECT_ROOT" || exit

# Loop through each image file in the folder
find "$IMAGE_FOLDER" -type f | while IFS= read -r image; do
    # Extract the filename without the path
    image_name=$(basename "$image")

    # If image file name contains "sponsor", skip it
    if [[ "$image_name" == *"sponsor"* ]]; then
        echo "Skipping sponsor image: $image_name"
        continue
    fi

    echo "Checking image: $image_name"

    # Search for the image name using rg and capture the result
    search_result=$(rg -F --files-with-matches "$image_name" \
        --no-ignore --hidden \
        --glob '!.git/*' \
        --glob '!$IMAGE_FOLDER/*' < /dev/null)

    echo "Search result: $search_result"

    # If rg doesn't find any matches, delete the image
    if [ -z "$search_result" ]; then
        echo "Deleting unused image: $image"
        rm "$image"
    else
        echo "Image used: $image_name"
        echo "$search_result"
    fi
done

echo "Cleanup completed!"
