const express = require('express')
const app = express()

app.use(express.static('public'))
app.set('view engine', 'ejs')

app.get('/', (req,res) => {
    res.render('index')
});

app.get('/constructorsPage.html', (req, res) => {
    res.render('constructorsPage')
})

app.get('/driversPage.html', (req, res) => {
    res.render('driversPage')
})

app.listen(3000)