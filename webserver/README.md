Using the start/stop shell scripts here, there are two `.env` files expected `.host.env` and `.docker.env`

The `.env` file should have the following settings (`AUTO_ADMIN` is optional)
```
GOOGLE_CLIENT_ID=<your GOOGLE_CLIENT_ID here>
GOOGLE_CLIENT_SECRET=<your GOOGLE_CLIENT_SECRET here>
JWT_SECRET=<your JWT_SECRET here>
REDIRECT_URL=<your REDIRECT_URL here>
BIND_ADDRESS=<your BIND_ADDRESS here>
DATABASE_PATH=./data/database.sqlite
AUTO_ADMIN=TheAdminUser@gmail.com
GIN_MODE=release
```
You probably want to leave the `AUTO_ADMIN` setting out of your production `.env`.