//conexion
const API = "https://auth-2fa-api.onrender.com/api"

let userId = null
let token = null

//login
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
document.getElementById("auth-box").style.display="none"
document.getElementById("dashboard").style.display="block"

document.getElementById("user-email").innerText =
"Bienvenido " + email

}

else{

document.getElementById("result").innerText=data.error || data.message

}

}

//Registro
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

//verificar 2FA
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

//Logout
function logout(){

token = null

document.getElementById("dashboard").style.display="none"
document.getElementById("auth-box").style.display="block"

}

async function enable2FA(){

const res = await fetch(`${API}/2fa/generate`,{

method:"POST",

headers:{
"Content-Type":"application/json",
"Authorization":`Bearer ${token}`
}

})

const data = await res.json()

document.getElementById("dashboard").style.display="none"
document.getElementById("twofa-setup").style.display="block"

document.getElementById("qr-image").src = data.qr

}

async function confirm2FA(){

const code = document.getElementById("verify-token").value

const res = await fetch(`${API}/2fa/verify`,{

method:"POST",

headers:{
"Content-Type":"application/json",
"Authorization":`Bearer ${token}`
},

body:JSON.stringify({
token:code
})

})

const data = await res.json()

if(data.message){

document.getElementById("twofa-setup").style.display="none"
document.getElementById("dashboard").style.display="block"

alert("2FA activado correctamente")

}else{

alert("Código incorrecto")

}

}

//Formulario cambio contraseña
function showChangePassword(){

document.getElementById("change-password").style.display="block"

}

//Cambiar contraseña
async function changePassword(){

const newPassword = document.getElementById("new-password").value

const res = await fetch(`${API}/change-password`,{

method:"POST",

headers:{
"Content-Type":"application/json",
"Authorization":`Bearer ${token}`
},

body:JSON.stringify({
newPassword:newPassword
})

})

const data = await res.json()

alert(data.message || data.error)

}

//Eliminar cuenta
async function deleteAccount(){

if(!confirm("¿Seguro que quieres eliminar tu cuenta?")){
return
}

const res = await fetch(`${API}/delete-user`,{

method:"DELETE",

headers:{
"Authorization":`Bearer ${token}`
}

})

const data = await res.json()

alert(data.message)

logout()

}