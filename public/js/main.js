const form = document.getElementById("send")
const errMessage = document.getElementById("error")

form.addEventListener('submit', async(e) => {
    e.preventDefault();

    const name = document.getElementById('name').value
    const email = document.getElementById('email').value
    const number = document.getElementById("number").value
    const msg = document.querySelector("textarea").value

    if (name.length < 3){
        errMessage.innerText = "Name must be at least 3 character!"
        return;
    }
    if (!email.includes('@') || !email.includes(".")){
        errMessage.innerText = "Email must have '@' and '.'. Maybe you should check your email!"
        return;
    }

    errMessage.innerText = ""

    try {
        const res = await fetch("http://localhost:3000/send-data", {
            method: "POST",
            headers: {"Content-type": "application/json"},
            body: JSON.stringify({
                name, email, number, msg
            })
        })

        const data = await res.json()
        for (i=0; i<data.length; i++){
            console.log(data[i])
        }
        document.getElementById("send").reset()
        alert("Message sent successfully!")
    } catch(error) {
        document.getElementById("error").textContent = "Something went wrong"
    }
})