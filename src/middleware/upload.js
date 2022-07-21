const multer = require('multer')
const HTTP = require('../../constants/responseCode.constant')
const maxSize = 1 * 1000 * 1000


const multerFilter = (req, file, cb) => {
    if (file.mimetype.split("/")[1] === "jpg" || file.mimetype.split("/")[1] === "jpeg" || file.mimetype.split("/")[1] === "png" ) {
        cb(null, true)
    } else {
        req.fileValidationError = "please select valid image format!"
        return cb(null, false, new Error("Only .jpg, .jpeg and .png format allowed!"))
    }
}

const storeAvatar = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, "uploads");
    },
    filename: (req, file, cb) => {
      const ext = file.mimetype.split("/")[1];
      cb(null, `/user-${file.fieldname}-${Date.now()}.${ext}`);
    },
});

const uploadAvatar = multer({
    fileFilter: multerFilter,
    limits: { fileSize: maxSize },
    storage: storeAvatar
})

module.exports = uploadAvatar
