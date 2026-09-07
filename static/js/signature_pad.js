document.addEventListener("DOMContentLoaded", function () {
    const canvas = document.getElementById("signature-canvas");
    const clearButton = document.getElementById("clear-signature");
    const signatureInput = document.getElementById("requester-signature");
    const form = document.getElementById("requisition-form");

    if (!canvas || !signatureInput || !form) {
        return;
    }

    const context = canvas.getContext("2d");
    let drawing = false;
    let hasSignature = false;

    context.strokeStyle = "#111111";
    context.lineWidth = 2;
    context.lineCap = "round";
    context.lineJoin = "round";

    function getPosition(event) {
        const rect = canvas.getBoundingClientRect();
        const source = event.touches ? event.touches[0] : event;

        return {
            x: (
                (source.clientX - rect.left)
                * canvas.width
                / rect.width
            ),
            y: (
                (source.clientY - rect.top)
                * canvas.height
                / rect.height
            )
        };
    }

    function startDrawing(event) {
        event.preventDefault();

        drawing = true;
        hasSignature = true;

        const position = getPosition(event);

        context.beginPath();
        context.moveTo(position.x, position.y);
    }

    function draw(event) {
        if (!drawing) {
            return;
        }

        event.preventDefault();

        const position = getPosition(event);

        context.lineTo(position.x, position.y);
        context.stroke();
    }

    function stopDrawing(event) {
        if (event) {
            event.preventDefault();
        }

        if (!drawing) {
            return;
        }

        drawing = false;
        context.closePath();
    }

    canvas.addEventListener("mousedown", startDrawing);
    canvas.addEventListener("mousemove", draw);
    window.addEventListener("mouseup", stopDrawing);

    canvas.addEventListener("touchstart", startDrawing, {
        passive: false
    });

    canvas.addEventListener("touchmove", draw, {
        passive: false
    });

    canvas.addEventListener("touchend", stopDrawing, {
        passive: false
    });

    if (clearButton) {
        clearButton.addEventListener("click", function () {
            context.clearRect(
                0,
                0,
                canvas.width,
                canvas.height
            );

            hasSignature = false;
            signatureInput.value = "";
        });
    }

    form.addEventListener("submit", function (event) {
        const clickedButton = event.submitter;
        const isSubmission = (
            clickedButton
            && clickedButton.value === "submit"
        );

        if (isSubmission && !hasSignature) {
            event.preventDefault();

            alert(
                "É necessário assinar antes de submeter a requisição."
            );

            return;
        }

        if (hasSignature) {
            signatureInput.value = canvas.toDataURL("image/png");
        }
    });
});
