// Binary Rain Animation
document.addEventListener('DOMContentLoaded', function() {
    const canvas = document.getElementById('binary-rain');
    const ctx = canvas.getContext('2d');

    // Set canvas size to window size
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    // Initial resize
    resizeCanvas();

    // Resize canvas when window is resized
    window.addEventListener('resize', resizeCanvas);

    // Binary rain drop class
    class BinaryDrop {
        constructor(x, y, speed, fontSize) {
            this.x = x;
            this.y = y;
            this.speed = speed;
            this.fontSize = fontSize;
            this.text = '';
            this.generateRandomBinary();
        }

        generateRandomBinary() {
            this.text = Math.random() > 0.5 ? '1' : '0';
        }

        draw() {
            // Create gradient for the text
            const gradient = ctx.createLinearGradient(this.x, this.y, this.x, this.y + this.fontSize);
            gradient.addColorStop(0, 'rgba(103, 126, 234, 0.8)');
            gradient.addColorStop(1, 'rgba(103, 126, 234, 0.2)');
            
            ctx.fillStyle = gradient;
            ctx.font = `${this.fontSize}px monospace`;
            ctx.fillText(this.text, this.x, this.y);
        }

        update() {
            this.y += this.speed;
            if (this.y > canvas.height) {
                this.y = 0;
                this.generateRandomBinary();
            }
        }
    }

    // Create binary drops
    const drops = [];
    const numberOfColumns = Math.floor(canvas.width / 20); // Adjust spacing between columns

    for (let i = 0; i < numberOfColumns; i++) {
        const x = i * 20;
        const y = Math.random() * canvas.height;
        const speed = Math.random() * 2 + 1;
        const fontSize = Math.random() * 5 + 15;
        drops.push(new BinaryDrop(x, y, speed, fontSize));
    }

    // Animation loop
    function animate() {
        // Semi-transparent black to create trail effect
        ctx.fillStyle = 'rgba(10, 5, 35, 0.1)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Update and draw drops
        drops.forEach(drop => {
            drop.draw();
            drop.update();
        });

        requestAnimationFrame(animate);
    }

    // Start animation
    animate();
}); 