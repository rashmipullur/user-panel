const express = require('express')
const router = express.Router()
const Task = require('../models/task')
const { authUser } = require('../middleware/auth')


router.post('/tasks', authUser, async (req, res) => {
    const task = new Task({
        ...req.body,    // spread syntax - to make shallow copie
        owner: req.user._id
    })
    try {
        await task.save()
        res.status(201).send(task)
    } catch(e) {
        res.status(400).send(e)
    }
})

router.patch('/tasks/:id', authUser, async (req, res) => {
    const updates = Object.keys(req.body)
    const allowedUpdates = ['description','timing']
    const isValidOperation = updates.every((update) => allowedUpdates.includes(update))

    if (!isValidOperation) {
        return res.status(400).send({ error: 'Invalid updates!' })
    }

    try {
        const task = await Task.findOne({_id: req.params.id, owner: req.user._id})
        if(!task) { return res.status(404).send() }
        updates.forEach((update) => task[update] = req.body[update])
        await task.save() 
        res.send(task)
    } catch(e) {
        res.status(400).send(e)
    }
})

router.get('/tasks', authUser, async (req, res) => {
    try {
        const task = await Task.find({ owner: req.user._id })
        if(!task) { return res.status(404).send() }
        res.send(task)
    } catch(e) {
        res.status(500).send()
    }
})

module.exports = router