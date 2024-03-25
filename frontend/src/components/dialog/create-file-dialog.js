import React from 'react';
import PropTypes from 'prop-types';
import { Button, Modal, ModalHeader, Input, ModalBody, ModalFooter, Form, FormGroup, Label, Alert } from 'reactstrap';
import { gettext } from '../../utils/constants';
import { Utils } from '../../utils/utils';

const propTypes = {
  fileType: PropTypes.string,
  parentPath: PropTypes.string.isRequired,
  onAddFile: PropTypes.func.isRequired,
  checkDuplicatedName: PropTypes.func.isRequired,
  toggleDialog: PropTypes.func.isRequired,
};

class CreateFile extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      parentPath: '',
      childName: props.fileType || '',
      errMessage: '',
      isSubmitBtnActive: props.fileType.slice(0, -5) ? true : false,
    };
    this.newInput = React.createRef();
  }

  componentDidMount() {
    let parentPath = this.props.parentPath;
    if (parentPath[parentPath.length - 1] === '/') {  // mainPanel
      this.setState({parentPath: parentPath});
    } else {
      this.setState({parentPath: parentPath + '/'}); // sidePanel
    }
  }

  handleChange = (e) => {
    if (!e.target.value.trim()) {
      this.setState({isSubmitBtnActive: false});
    } else {
      this.setState({isSubmitBtnActive: true});
    }

    this.setState({
      childName: e.target.value,
    }) ;
  };

  handleSubmit = () => {
    if (!this.state.isSubmitBtnActive) {
      return;
    }

    let isDuplicated = this.checkDuplicatedName();
    let newName = this.state.childName;

    if (isDuplicated) {
      let errMessage = gettext('The name "{name}" is already taken. Please choose a different name.');
      errMessage = errMessage.replace('{name}', Utils.HTMLescape(newName));
      this.setState({errMessage: errMessage});
    } else {
      let path = this.state.parentPath + newName;
      this.props.onAddFile(path);
      this.props.toggleDialog();
    }
  };

  handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      this.handleSubmit();
      e.preventDefault();
    }
  };

  checkDuplicatedName = () => {
    let isDuplicated = this.props.checkDuplicatedName(this.state.childName);
    return isDuplicated;
  };

  onAfterModelOpened = () => {
    if (!this.newInput.current) return;
    this.newInput.current.focus();
    this.newInput.current.setSelectionRange(0,0);
  };

  render() {
    const { toggleDialog } = this.props;
    return (
      <Modal isOpen={true} toggle={toggleDialog} onOpened={this.onAfterModelOpened}>
        <ModalHeader toggle={toggleDialog}>{gettext('New File')}</ModalHeader>
        <ModalBody>
          <Form>
            <FormGroup>
              <Label for="fileName">{gettext('Name')}</Label>
              <Input
                id="fileName"
                onKeyDown={this.handleKeyDown}
                innerRef={this.newInput}
                value={this.state.childName}
                onChange={this.handleChange}
              />
            </FormGroup>
          </Form>
          {this.state.errMessage && <Alert color="danger" className="mt-2">{this.state.errMessage}</Alert>}
        </ModalBody>
        <ModalFooter>
          <Button color="secondary" onClick={toggleDialog}>{gettext('Cancel')}</Button>
          <Button color="primary" onClick={this.handleSubmit} disabled={!this.state.isSubmitBtnActive}>{gettext('Submit')}</Button>
        </ModalFooter>
      </Modal>
    );
  }
}

CreateFile.propTypes = propTypes;

export default CreateFile;
