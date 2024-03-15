from typing import Any, List, Union

from fastapi import HTTPException
from sqlalchemy.orm import Session


def get_db_single_object_by_email(
    db: Session,
    model: Any,
    email: str,
    exception: HTTPException,
    expect_none=False,
) -> Union[Any, None]:
    """
    Retrieves a single object from the database based on the provided email.

    Args:
        db (Session): The SQLAlchemy database session.
        model (Any): The SQLAlchemy model representing the database table.
        email (str): The email address used to query the database.
        exception (HTTPException): The HTTP exception to raise if the object is not found
            of if found and expecting None.
        expect_none (bool, optional): If True, expects no objects to be found and raises
            the specified exception if an object is found. Defaults to False.

    Returns:
        Union[Any, None]: The retrieved object if found, None if no object is found.

    Raises:
        HTTPException: If the expect_none flag is False and no object is found.

    Note:
        This function assumes that the provided model has an 'email' attribute
        representing the email address column in the corresponding database table.
    """
    objects = db.query(model).where(model.email == email).all()
    objects_len = len(objects)
    if expect_none:
        if objects_len:
            raise exception
        return
    if not objects_len:
        raise exception
    return objects[0]


def get_db_list_of_objects_by_list_of_ids(
    db: Session, model: Any, list_of_ids: List[int]
) -> List[Any]:
    """
    Retrieves a list of objects from the database based on the provided list of IDs.

    Args:
        db (Session): The SQLAlchemy database session.
        model (Any): The SQLAlchemy model representing the database table.
        list_of_ids (List[int]): A list of integer IDs to filter the objects.

    Returns:
        List[Any]: A list of objects from the database matching the provided IDs.
    """
    return db.query(model).where(model.id.in_(list_of_ids)).all()
