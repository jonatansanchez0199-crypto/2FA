const API = "https://auth-2fa-api.onrender.com/api"

let userId = null
let token = null

async function login(){

const email = document.getElementById("email").value
const password = document.getElementById("password").value

const res = await fetch(`${API}/login`,{
method:"POST",
headers:{
"Content-Type":"application/json"
},
body:JSON.stringify({email,password})
})

const data = await res.json()

if(data.message === "2FA requerido"){

userId = data.userId

document.getElementById("auth-box").style.display="none"
document.getElementById("twofa-box").style.display="block"

}

else if(data.token){

token = data.token
document.getElementById("result").innerText="Login exitoso"

}

else{

document.getElementById("result").innerText=data.error

}

}

async function register(){

const email = document.getElementById("email").value
const password = document.getElementById("password").value

const res = await fetch(`${API}/register`,{

method:"POST",
headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({email,password})

})

const data = await res.json()

document.getElementById("result").innerText = "Usuario creado"

}

async function verify2FA(){

const code = document.getElementById("token").value

const res = await fetch(`${API}/login/2fa`,{

method:"POST",
headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({
userId:userId,
token:code
})

})

const data = await res.json()

if(data.token){

token = data.token

document.getElementById("twofa-box").style.display="none"

document.getElementById("result").innerText="Login con 2FA exitoso"

}

else{

document.getElementById("result").innerText=data.error

}

}