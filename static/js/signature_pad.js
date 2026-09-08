document.addEventListener("DOMContentLoaded", function () {
    const canvas = document.getElementById("signature-canvas");
    const form = document.getElementById("requisition-form");
    const signatureInput = document.getElementById("requester-signature");
    const clearButton = document.getElementById("clear-signature");

    if (!canvas || !form || !signatureInput) {
        console.error("Elementos da assinatura não encontrados.");
        return;
    }

    const context = canvas.getContext("2d");

    let drawing = false;
    let hasSignature = false;

    context.strokeStyle = "#000000";
    context.lineWidth = 3;
    context.lineCap = "round";
    context.lineJoin = "round";

    function getPosition(event) {
        const rectangle = canvas.getBoundingClientRect();

        return {
            x: (event.clientX - rectangle.left)
                * (canvas.width / rectangle.width),

            y: (event.clientY - rectangle.top)
                * (canvas.height / rectangle.height)
        };
    }

    function startDrawing(event) {
        event.preventDefault();

        drawing = true;
        hasSignature = true;

        const position = getPosition(event);

        context.beginPath();
        context.moveTo(position.x, position.y);

        canvas.setPointerCapture(event.pointerId);
    }

    function continueDrawing(event) {
        if (!drawing) {
            return;
        }

        event.preventDefault();

        const position = getPosition(event);

        context.lineTo(position.x, position.y);
        context.stroke();
    }

    function stopDrawing(event) {
        if (!drawing) {
            return;
        }

        event.preventDefault();

        drawing = false;
        context.closePath();
    }

    canvas.addEventListener("pointerdown", startDrawing);
    canvas.addEventListener("pointermove", continueDrawing);
    canvas.addEventListener("pointerup", stopDrawing);
    canvas.addEventListener("pointercancel", stopDrawing);
    canvas.addEventListener("pointerleave", stopDrawing);

    if (clearButton) {
        clearButton.addEventListener("click", function () {
            context.clearRect(
                0,
                0,
                canvas.width,
                canvas.height
            );

            signatureInput.value = "";
            hasSignature = false;
        });
    }

    form.addEventListener("submit", function (event) {
        const submitButton = event.submitter;

        const isFinalSubmission =
            submitButton &&
            submitButton.name === "submit_action" &&
            submitButton.value === "submit";

        if (isFinalSubmission && !hasSignature) {
            event.preventDefault();

            alert(
                "Tem de assinar a requisição antes de submeter."
            );

            canvas.scrollIntoView({
                behavior: "smooth",
                block: "center"
            });

            return;
        }

        if (hasSignature) {
            signatureInput.value = canvas.toDataURL("image/png");
        }
    });
});
