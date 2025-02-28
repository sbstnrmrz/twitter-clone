const loginForm = document.getElementById('login-form');
const createAccountForm = document.getElementById('create-account-form');
const showCreateAccountLink = document.getElementById('create-account');
const showLoginLink = document.getElementById('login');
const createAccountError = document.getElementById('create-account-error');
const loginError = document.getElementById('login-error');

showCreateAccountLink.addEventListener('click', (e) => {
    e.preventDefault();
    loginForm.classList.add('hidden');
    createAccountForm.classList.remove('hidden');
    createAccountError.textContent = ''; // Clear error on switch
});

showLoginLink.addEventListener('click', (e) => {
    e.preventDefault();
    createAccountForm.classList.add('hidden');
    loginForm.classList.remove('hidden');
    createAccountError.textContent = ''; // Clear error on switch
});

createAccountForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const name = document.getElementById('create-name').value;
    const username = document.getElementById('create-username').value;
    const password = document.getElementById('create-password').value;
    console.log(`create account:`)
    console.log(`  name: ${name}`)
    console.log(`  username: ${username}`)
    console.log(`  password: ${password}`)

    const formData = new FormData(createAccountForm); // Collect form data

    try {
        const response = await fetch('/create-account', {
            method: 'POST',
            body: formData,
        });

        const data = await response.json();

        if (data.error) {
            createAccountError.textContent = data.error;
        } else {
            alert("Account created successfully!");
            createAccountForm.reset();
            createAccountError.textContent = "";
            loginForm.classList.remove('hidden');
            createAccountForm.classList.add('hidden');
        }
    } catch (error) {
        console.error("Error:", error);
        createAccountError.textContent = "An error occurred. Please try again.";
    }
});

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('create-username').value;
    const password = document.getElementById('create-password').value;
    console.log(`login:`)
    console.log(`  username: ${username}`)
    console.log(`  password: ${password}`)

    const formData = new FormData(loginForm);

    try {
        const response = await fetch('/login', {
            method: 'POST',
            body: formData,
        });

        const data = await response.json();

        if (data.error) {
            loginError.textContent = data.error;
        } else {
            alert("Login success");
            loginForm.reset();
            loginError.textContent = "";
        }
    } catch (error) {
        console.error("Error:", error);
        loginError.textContent = "An error occurred. Please try again.";
    }
});
