# Finsta

A website made in python using flask, MySQL, HTML, and CSS using Boostrap library.
This website allows users to view, post, and react to images.

## How it works
- Uses bcrypt to add a salt to a password for user authentication.
- Supports follow requests and tag requests.
- When users choose to follow a user, a notification appears to the followee to accept or deny this request.
- Followers are able to view images posted by the followee.
- Supports tag requests.  A tagee can accept or deny a tag.
- Supports comments and reactions.
- **Includes a seven line SQL query!**
- Allows users to look for friends using a fuzzy search algorithm.
- Supports friend groups which allows users to invite and remove people from friend groups.

An implementation can be seen here below:

![Finsta](https://github.com/seamusgould/Finsta/blob/master/Finsta.gif?raw=true))