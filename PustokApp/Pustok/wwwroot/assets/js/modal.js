const modalBtns = document.getElementsByClassName("modal-btn");
const modalContent = document.querySelector('.modal-dialog');
for (const btn of modalBtns) {
    btn.addEventListener("click", (e) => {
        e.preventDefault();
        let link = btn.getAttribute("href");
        console.log(link);


        fetch(link)
        .then(response => response.text())
        .then(data=> {
            console.log(data)
            modalContent.innerHTML = data;
         })

    })
}

$(document).on("click", ".add-to-basket", function (e) {
    e.preventDefault();
    let link = $(this).attr("href");
  

    fetch(link)
        .then(response => {
            if (!response.ok) {
                Swal.fire({
                    title: 'Error!',
                    text: 'This product is out of stock',
                    icon: 'error',
                    confirmButtonText: 'Ok'
                })
                throw new Error("product out of stock");
                return;
            }
            return response.text();
        })
        .then(data => {
            Swal.fire({
                position: 'center',
                icon: 'success',
                title: 'Added',
                showConfirmButton: false,
                timer: 1200
            })
            $("#BasketPartialHolder").html(data);
        })
        .catch(error=>{
        console.log(error)
             })

    
})

$(document).on("click", ".removeItem", function (e) {
    e.preventDefault();

    let link = $(this).attr("href");

    fetch(link)
    .then(response => {
        if (!response.ok) {
            Swal.fire({
                title: 'Error!',
                text: 'This product is out of stock',
                icon: 'error',
                confirmButtonText: 'Ok'
            })
            throw new Error("something went wrong");
            return;
        }
        return response.text();
    })
        .then(data => {


            console.log(data)
            $("#BasketPartialHolder").html(data);
        })
        .catch(error => {
            console.log(error)
        })
  
})






$(document).on("click", ".add-basket-count", function (e) {
    e.preventDefault();
    let link = $(this).attr("href");
    let quantity = document.getElementById("quantity").value;
    link += `&count=${quantity}`;
    console.log(link)
    fetch(link)
        .then(response => {
            if (!response.ok) {
                Swal.fire({
                    title: 'Error!',
                    text: 'This product is out of stock',
                    icon: 'error',
                    confirmButtonText: 'Ok'
                })
                throw new Error("product out of stock");
                return;
            }
            return response.text();
        })
        .then(data => {
            Swal.fire({
                position: 'center',
                icon: 'success',
                title: 'Added',
                showConfirmButton: false,
                timer: 1200
            })
            $("#BasketPartialHolder").html(data);
        })
        .catch(error => {
            console.log(error)
        })


})
