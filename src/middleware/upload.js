// const multer = require('multer')
// const multerS3 = require('multer-s3')
// const HTTP = require('../../constants/responseCode.constant')
// const maxSize = 1 * 1000 * 1000

// const s3 = new S3Client()

// const multerFilter = (req, file, cb) => {
//     if (file.mimetype.split("/")[1] === "jpg" || file.mimetype.split("/")[1] === "jpeg" || file.mimetype.split("/")[1] === "png" ) {
//         cb(null, true)
//     } else {
//         req.fileValidationError = "please select valid image format!"
//         return cb(null, false, new Error("Only .jpg, .jpeg and .png format allowed!"))
//     }
// }



// const uploadAvatar = multer({
//     fileFilter: multerFilter,
//     limits: { fileSize: maxSize },
//     storage: storeAvatar
// })

// module.exports = {
//     multerFilter,
//     uploadAvatar
// }