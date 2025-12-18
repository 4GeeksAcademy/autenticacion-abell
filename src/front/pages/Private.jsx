import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Table, Button, Container, Row, Col, Modal, Form } from "react-bootstrap";
import { getToken, removeToken } from "../utils/auth";

export default function Private() {
    const navigate = useNavigate();
    const [users, setUsers] = useState([]);
    const [showModal, setShowModal] = useState(false);
    const [selectedUser, setSelectedUser] = useState(null);
    const [newEmail, setNewEmail] = useState("");
    const BASE = import.meta.env.VITE_BACKEND_URL || '';

    const token = getToken();

    useEffect(() => {
        if (!token) {
            navigate("/login");
            return;
        }
        fetchUsers();
    }, [navigate]);

    const fetchUsers = () => {
        fetch(`${BASE}/users`, {
            headers: { Authorization: `Bearer ${token}` },
        })
            .then((res) => res.json())
            .then((data) => setUsers(data))
            .catch((err) => console.error(err));
    };

    const handleLogout = () => {
        removeToken();
        navigate("/login");
    };

    const handleEdit = (user) => {
        setSelectedUser(user);
        setNewEmail(user.email);
        setShowModal(true);
    };

    const handleSave = () => {
        if (!selectedUser) return;
        fetch(`${BASE}/users/${selectedUser.id}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ email: newEmail }),
        })
            .then((res) => {
                if (!res.ok) throw new Error("Failed to update");
                return res.json();
            })
            .then(() => {
                setShowModal(false);
                fetchUsers();
            })
            .catch((err) => console.error(err));
    };

    const handleDelete = (id) => {
        if (!window.confirm("¿Seguro que quieres eliminar este usuario?")) return;
        fetch(`${BASE}/users/${id}`, {
            method: "DELETE",
            headers: { Authorization: `Bearer ${token}` },
        })
            .then((res) => {
                if (!res.ok) throw new Error("Failed to delete");
                fetchUsers();
            })
            .catch((err) => console.error(err));
    };

    return (
        <Container className="mt-4">
            <Row className="mb-3">
                <Col>
                    <h2>Bienvenido a la ruta privada</h2>
                </Col>
                <Col className="text-end">
                    <Button variant="danger" onClick={handleLogout}>
                        Cerrar sesión
                    </Button>
                </Col>
            </Row>

            <Table striped bordered hover responsive>
                <thead className="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Email</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    {users.length > 0 ? (
                        users.map((user) => (
                            <tr key={user.id}>
                                <td>{user.id}</td>
                                <td>{user.email}</td>
                                <td>
                                    <Button variant="warning" size="sm" onClick={() => handleEdit(user)}>
                                        Editar
                                    </Button>{' '}
                                    <Button variant="danger" size="sm" onClick={() => handleDelete(user.id)}>
                                        Eliminar
                                    </Button>
                                </td>
                            </tr>
                        ))
                    ) : (
                        <tr>
                            <td colSpan="3" className="text-center">
                                No hay usuarios registrados
                            </td>
                        </tr>
                    )}
                </tbody>
            </Table>

            <Modal show={showModal} onHide={() => setShowModal(false)}>
                <Modal.Header closeButton>
                    <Modal.Title>Editar Usuario</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Form>
                        <Form.Group>
                            <Form.Label>Email</Form.Label>
                            <Form.Control type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
                        </Form.Group>
                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="secondary" onClick={() => setShowModal(false)}>
                        Cancelar
                    </Button>
                    <Button variant="primary" onClick={handleSave}>
                        Guardar
                    </Button>
                </Modal.Footer>
            </Modal>
        </Container>
    );
}
